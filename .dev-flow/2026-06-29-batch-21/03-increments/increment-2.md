# Increment 2 — HLR-030 (US-026 change-file dropdown)

> A `Select` dropdown lists `patches/*.json`; selecting one loads that change document (consumes Inc1's folder). 3 files. **code-reviewer: APPROVE-WITH-NITS** (0 HIGH/MED); the one security-relevant LOW was folded.

## 1. What changed
`Select#patch_doc_file_select` added to the change-file row; `set_change_files()` populates it (mirrors `set_variants`); the app scans `workarea/patches/*.json` (sorted), populates on patch-screen activation AND after each save (R2), and on `Select.Changed` loads the chosen file via the existing `ChangeService.load`. F1 read-path containment guard added (skip symlinks at scan + assert `is_relative_to(patches/)` at load).

## 2. Files modified (3 — Inc2 incremental)
- `s19_app/tui/screens_directionb.py` — LLR-030.1 `Select(allow_blank=True)` (:648-651) + `Select.Changed` handler (:889); LLR-030.2 `set_change_files` (:549, `set_options` :587).
- `s19_app/tui/app.py` — LLR-030.3 `_scan_patch_change_files` (sorted, symlink-skip :2238) + `_prefill_patch_change_files` after save (R2, :1428-1431) + `ChangeFileSelected` load handler with F1 containment guard (:2315-2322).
- `tests/test_tui_patch_editor_v2.py` — AT-030a (+R2 sub), AT-030b, AT-030c, TC-030, F1 symlink test.

## 3. How to test
```
python -m pytest tests/test_tui_patch_editor_v2.py -k "030 or symlink" -q
python -m pytest -q -m "not slow"
python -m ruff check s19_app/tui/screens_directionb.py s19_app/tui/app.py tests/test_tui_patch_editor_v2.py
```

## 4. Test results
- 6 green: `test_at030a_dropdown_lists_and_loads_selected_change_file` (C-12 gate), `test_at030a_r2_save_while_open_appears_without_reactivation`, `test_at030b_empty_patches_folder_renders_placeholder_no_crash`, `test_at030c_directly_dropped_file_is_listed_and_loadable`, `test_tc030_scan_returns_sorted_json_set_ignoring_non_change_files`, `test_f1_symlink_entry_is_skipped_by_scan`.
- **Counterfactual RED (QC-2, captured by code-reviewer):** neuter `_scan_patch_change_files`→`[]` ⇒ `test_at030a` RED (`InvalidSelectValueError: Illegal select value 'changes_1.json'` — the second file, selected by known filename, can't list/load). Restored → green.
- Full non-slow (post-F1-fold, confirmed): **951 passed / 29 skipped / 3 xfailed / 0 failed** = 977 → **983 collected (+6)**. ruff clean. **Frozen-engine diff 0** (vs origin/main ec3a2a7; `test_engine_unchanged` green).

## 5. Independent review + folds
- **code-reviewer: APPROVE-WITH-NITS.** C-12 gate genuine (selects by known filename `_name_holding_address(patches, 0x200)`, asserts active doc's first entry = 0x200 — C-10 non-default+content, not len>0). F1 security test portable (the `is_relative_to` guard runs unconditionally via `ChangeFileSelected("../outside.json")`; symlink-specific assert is `if symlink_made`-guarded → not a Windows no-op). W1/W2 empty-set safe; R2 refresh real; sorted scan + select-by-name.
- **F1 LOW FOLDED (security-relevant):** the load-path `candidate.is_symlink()` was on the RESOLVED path (dead — `resolve()` follows the symlink). Fixed to check the UNRESOLVED path (`raw.is_symlink()`), making the guard live + consistent with the scan-time skip. 6 tests + ruff re-confirmed green after the fold.
- **F2 (informational):** the scan skipping ALL symlinks is stricter than "optionally skip" — safe direction, no action.

## 6. Process note
The implementing `software-dev` agent STALLED without delivering a review packet (94 tool calls, then a "wait for monitor" no-op — same failure mode as the batch-20 Phase-4 qa agent). Orchestrator reconstructed verification directly (disk inspection + targeted test runs) and had `code-reviewer` capture the counterfactual RED. Reinforces the batch-20 "checkpoint-before-long-run" carry → Phase 5.

## 7. Pending / next
- **Inc3 (HLR-032 Checks clarity)** — description Label "Checks: runs the loaded change document's checks against the loaded image." (`screens_directionb.py` + `styles.tcss`).
