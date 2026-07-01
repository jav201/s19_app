# Traceability Matrix — s19_app TUI — Batch 2026-06-29-batch-21

> Feature #8 patch-editor, slice 1: change-file management (save destination + load dropdown) + Checks clarity.
> Two chains per story — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
> All rows complete, all nodes PASS, zero gaps/orphans.

---

## 1. Master table — functional chain (white-box)

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-026 | HLR-030 | LLR-030.1 | TC-030 | `s19_app/tui/app.py:2217-2240` | pass | `_scan_patch_change_files` — sorted `.json` set, ignores non-change files, symlink-skip |
| US-026 | HLR-030 | LLR-030.2 | TC-030 | `s19_app/tui/screens_directionb.py:549`, `:587` | pass | `set_change_files` populates `Select#patch_doc_file_select` |
| US-026 | HLR-030 | LLR-030.3 | TC-030 | `s19_app/tui/screens_directionb.py:889` | pass | `Select.Changed` handler → `ChangeService.load` |
| US-027 | HLR-031 | LLR-031.1 | TC-031 | `s19_app/tui/workspace.py:19`, `:47-48` | pass | `WORKAREA_PATCHES="patches"` const + `ensure_workarea` mkdir |
| US-027 | HLR-031 | LLR-031.2 | TC-031 | `s19_app/tui/changes/io.py:1354` | pass | `write_change_document` places save under `workarea/patches/` |
| US-029 | HLR-032 | LLR-032.1 | — | `s19_app/tui/screens_directionb.py:665-670` | pass | `#patch_checks_help` description Label (static text; covered by AT-032a/b) |
| US-029 | HLR-032 | LLR-032.2 | — | `s19_app/tui/styles.tcss:680-685` | pass | Label CSS (covered by AT-032a/b) |

## 1b. Behavioral chain (black-box)

> Per user story: the acceptance test that observes the outcome through the shipped surface.

| US | Acceptance test (`AT-NNN`) | Shipped surface | Observed outcome / deliverable | Status |
|----|----------------------------|-----------------|--------------------------------|--------|
| US-026 | **AT-030a** *(C-12 through-surface GATE)* — `tests/test_tui_patch_editor_v2.py::test_at030a_dropdown_lists_and_loads_selected_change_file` | Patch screen `Select#patch_doc_file_select` | Dropdown lists a **handler-produced** saved change file; selecting it loads it via `ChangeService.load` | pass |
| US-026 | AT-030a-R2 — `::test_at030a_r2_save_while_open_appears_without_reactivation` | Patch screen dropdown | A save while the screen is open appears in the dropdown without re-activation (post-save prefill) | pass |
| US-026 | AT-030b — `::test_at030b_empty_patches_folder_renders_placeholder_no_crash` | Patch screen dropdown | Empty `patches/` renders a placeholder, no crash | pass |
| US-026 | **AT-030c** *(consumer guard)* — `::test_at030c_directly_dropped_file_is_listed_and_loadable` | Patch screen dropdown | A change file dropped directly into `patches/` (not produced this session) is listed and loadable | pass |
| US-026 | **F1** *(security-adversarial)* — `::test_f1_symlink_entry_is_skipped_by_scan` | `_scan_patch_change_files` scan | A symlink entry in `patches/` is skipped by the scan (read-path containment) | pass |
| US-027 | AT-031a — `tests/test_tui_patch_editor_v2.py::test_at031a_save_doc_lands_in_patches_folder` | `write_change_document` save | Saved change document lands in `workarea/patches/`, not the workarea root | pass |
| US-027 | AT-031b — `::test_at031b_two_saves_are_distinct_no_clobber` | `write_change_document` save | Two saves are distinct on disk — no clobber | pass |
| US-029 | AT-032a — `tests/test_tui_patch_editor_v2.py::test_at032a_checks_help_states_what_and_which_artifact` | `#patch_checks_help` Label | Help text states WHAT Checks does and WHICH artifact it runs against | pass |
| US-029 | AT-032b — `::test_at032b_clarity_added_action_wiring_unchanged` | Checks button + `run_checks` action | Clarity added; button id + action wiring unchanged | pass |

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 3 (US-026, US-027, US-029) |
| Covered user stories | 3 (100%) |
| Total HLR | 3 (HLR-030, HLR-031, HLR-032) |
| Implemented HLR | 3 (100%) |
| Total LLR | 7 |
| Implemented LLR | 7 (100%) |
| Test cases (TC) | 2 (TC-030, TC-031) |
| TC pass | 2 |
| TC fail | 0 |
| TC pending | 0 |
| Acceptance tests (AT) + adversarial | 9 (incl. F1) |
| AT pass | 9 |
| Total test nodes (AT + TC) | 11 |
| Node PASS | 11 (100%) |

> Full non-slow suite: 953 passed / 0 failed. Ledger 974 → 985 (+11). Frozen-engine diff = 0.

---

## 3. Detected gaps

*None.* Every user story has a complete functional chain AND a behavioral row; every node PASS; no requirement without a mapped node; no node without a code mapping.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | No gaps | — |

> **Deferred (out of this slice, tracked as BACKLOG — not gaps):** US-028 (change-file delete/rename from the dropdown), US-030, US-031. See `functionality.md` §"Deferred".

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | HLR-030 / US-026 | Patch-editor dropdown lists + loads change files from `patches/` |
| new | HLR-031 / US-027 | Change-document saves routed to dedicated `patches/` folder (was workarea root) |
| new | HLR-032 / US-029 | Checks button gains a description Label (what/which-artifact) |
| new | const `WORKAREA_PATCHES` | `workspace.py:19` + `ensure_workarea` mkdir `:47-48` |
| new | security node F1 | Read-path containment guard (symlink-skip at scan + `is_relative_to(patches/)` at load) |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-026** → HLR-030 → LLR-030.1, LLR-030.2, LLR-030.3 → TC-030 · AT-030a (GATE), AT-030a-R2, AT-030b, AT-030c (guard), F1 (security)
- **US-027** → HLR-031 → LLR-031.1, LLR-031.2 → TC-031 · AT-031a, AT-031b
- **US-029** → HLR-032 → LLR-032.1, LLR-032.2 → AT-032a, AT-032b

### 5.2 By code file
- `s19_app/tui/workspace.py` → LLR-031.1 → TC-031 (AT-031a/b)
- `s19_app/tui/changes/io.py` → LLR-031.2 → TC-031 (AT-031a/b)
- `s19_app/tui/app.py` → LLR-030.1 → TC-030 (AT-030a/-R2/b/c, F1) *(`_scan_patch_change_files` :2217-2240, `_prefill_patch_change_files` :1428-1431, load handler + F1 containment :2315-2322)*
- `s19_app/tui/screens_directionb.py` → LLR-030.2, LLR-030.3 (Select + handler), LLR-032.1 (`#patch_checks_help`) → TC-030 (AT-030*), AT-032a/b
- `s19_app/tui/styles.tcss` → LLR-032.2 → AT-032a/b
- `tests/test_tui_patch_editor_v2.py` → AT-030*, AT-031*, AT-032*, F1
- `tests/test_unified_write.py` → TC-031

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | 2026-06-29-batch-21 |
| Closing date | 2026-06-30 |
| Total iterations (sum of phases) | single-iteration per phase (0 blockers) |
| Validation passed | yes (953 passed / 0 failed; 11/11 nodes PASS) |
| Frozen-engine diff | 0 |
| Synced to Obsidian | pending (`/dev-flow-sync` after merge) |
