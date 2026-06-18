# Traceability Matrix — s19_app — Batch 2026-06-17-batch-13

> **Audience:** engineering / QA reviewers and the batch closer.
> **Purpose:** prove every user story traces down to a real, passing test node, with file:line evidence.
> **Source of truth:** `01-requirements.md` (§3/§4 HLR/LLR), `04-validation.md` (real node ids + PASS results, reconciled at Phase 4).
> All node ids below are the REAL names confirmed on disk at Phase 4 (`pytest --collect-only`), not the provisional `crc_config_load_*` selectors used in §5.2. **Verdict: PASS — 6/6 LLRs covered, 0 blocker fails.**

---

## 1. Master chain — US → HLR → LLR → TC → status → evidence

| US | HLR | LLR | TC | Real test node id | Status | Evidence (file:line) |
|----|-----|-----|----|-------------------|--------|----------------------|
| US-013 | HLR-013 | LLR-013.1 — config-path `Input` + "Load config" `Button` placement | TC-201 | `tests/test_tui_crc_surface.py::test_crc_config_load_widgets_present_and_toggle` | **PASS** | widgets `#operation_config_path` + `#operation_config_load` present + display-toggle on/off the CRC row (`screens.py:742-772` `_sync_config_visibility`) |
| US-013 | HLR-013 | LLR-013.2 — resolve + size-cap + read raw text into `#operation_config` (no parse) | TC-202 (unit) | `tests/test_crc_config.py::test_read_crc_config_text_returns_raw_text_without_parsing` (+3 sibling unit cases) | **PASS** | raw `str` returned, `parse_crc_config` NOT invoked; new reader `read_crc_config_text` in `crc_config.py` (NON-frozen) |
| US-013 | HLR-013 | LLR-013.2 — same (integration, through handler) | TC-203 | `tests/test_tui_crc_surface.py::test_crc_config_load_ok_populates_editor_via_handler` | **PASS** | byte-equal load THROUGH `on_button_pressed` → `_load_config_from_path` → `read_crc_config_text` (`screens.py:795 / 801 / 841`) |
| US-013 | HLR-013 | LLR-013.3 — load fault surfaces + no check run; dummy stays | TC-204 | `tests/test_tui_crc_surface.py::test_crc_config_load_fault_surfaces_error_and_no_check` (+ `..._error_surfaces_error_and_no_match`; + unit `test_read_crc_config_text_unresolvable_path_collects_one_error`) | **PASS** | fault → exactly 1 error, editor unchanged, 0 CRC checks; mount `#operation_config.text == DUMMY_CONFIG_TEXT` (`crc_config.py:47`, `screens.py:668`) |
| US-014 | HLR-014 | LLR-014.1 — `DUMMY_CHANGESET_TEXT` pre-loaded editable reference | TC-205 (integration) | `tests/test_tui_patch_editor_v2.py::test_paste_textarea_preloads_dummy_changeset` | **PASS** | mount paste `TextArea.text == DUMMY_CHANGESET_TEXT` (`.rstrip("\n")` tolerance, F-Q-07); id `#patch_paste_text` |
| US-014 | HLR-014 | LLR-014.1 — dummy is a valid `s19app-changeset` (kind=change) | TC-206 (unit) | `tests/test_changes_schema.py::test_dummy_changeset_parses` | **PASS** | dummy parses through `parse_change_document` with `kind == "change"`, ≥1 entry, 0 ERROR `ValidationIssue` |
| US-014 | HLR-014 | LLR-014.1 — changeset tripwire (FAKE data never leaks as a real file) | TC-211 | `tests/test_changes_schema.py::test_no_changeset_under_examples` | **PASS** | `examples/**/*changeset*.json` empty — git-tracked AND on-disk (mirrors CRC tripwire TC-114, F-S-04) |
| US-014 | HLR-014 | LLR-014.2 — paste text→document parse parity (string vs file) | TC-207 | `tests/test_changes_schema.py::test_parse_from_string_matches_file_read` | **PASS** | `entries` + `{issue.code}` equal to the file read (narrowed oracle, F-Q-04); `source_path=None` divergence asserted vs file read |
| US-014 | HLR-014 | LLR-014.2 — malformed paste → `MF-JSON-PARSE` (collect-don't-abort) | TC-209 | `tests/test_changes_schema.py::test_parse_malformed_json_emits_mf_json_parse` | **PASS** | malformed string → exactly `MF-JSON-PARSE`, 0 raises (3-exception catch re-homed around `json.loads`, F-A-01) |
| US-014 | HLR-014 | LLR-014.2 — refactor is delegation, not duplication | TC-210 | `tests/test_changes_schema.py::test_read_change_document_delegates_to_parse` | **PASS** | `read_change_document(path)` invokes `parse_change_document` exactly once (`call_count == 1`, F-Q-01) |
| US-014 | HLR-014 | LLR-014.2 — `parse_paste` action routes panel → service | TC-208 (route half) | `tests/test_tui_patch_editor_v2.py::test_paste_parse_then_apply_matches_file_loaded` | **PASS** | `ActionRequested(action="parse_paste", paste_text=…)` → router `elif` → `service.load_text` (`app.py:1336-1338`) |
| US-014 | HLR-014 | LLR-014.3 — parsed doc feeds the EXISTING apply/containment path (no new write) | TC-208 (apply + save-back half) | `tests/test_tui_patch_editor_v2.py::test_paste_parse_then_apply_matches_file_loaded` | **PASS** | identical apply outcome + save-back prompt-name identity vs a file-loaded doc (F-A-06); drives the existing `apply_doc` router (`app.py:1335` region, UNCHANGED) |
| US-014 | HLR-014 | action-set contract (REUSE-extend) — `PATCH_ACTIONS_V2` extended 9→10 | action-set | `tests/test_tui_patch_editor_v2.py::test_action_routing_pins_exactly_ten_v2_actions` | **PASS** | the fixed action frozenset asserted = 10 tokens after adding `parse_paste` (`app.py:126-138`); renamed `nine→ten` (planned REUSE-extend, not a new TC) |

---

## 2. LLR-014.3 standing write-surface gate (HARD Phase-4 row)

> This is the load-bearing assurance that US-014 introduces **0 new write code paths** — the pasted changeset is exactly as contained as a file-loaded one. Baseline = **`febd843`** (real batch-13 base / PR #17 merge / `origin/main` tip), NOT the stale local `main` ref `ec453a2` (§6.5 Amendment A-1).

| Gate check | Command | Result | Status |
|------------|---------|--------|--------|
| 3-file write surface unchanged | `git diff febd843 -- s19_app/tui/changes/apply.py s19_app/tui/changes/verify.py s19_app/tui/workspace.py` | **empty (0 changed lines)** | **PASS** |
| `emit_s19_from_mem_map` body unchanged | `git diff febd843 -- s19_app/tui/changes/io.py` (hunk inspection) | io.py hunks confined to `__all__` + new `parse_change_document` + `read_change_document` refactor; `emit_s19_from_mem_map` (`io.py:1300`) NOT in any hunk | **PASS** |
| `save_patched` body unchanged | `git diff febd843 -- s19_app/tui/services/change_service.py` (hunk inspection) | diff = import line + new `load_text` (`:630`) only; `save_patched` (`:807`) NOT in any hunk | **PASS** |

---

## 3. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 2 (US-013, US-014) |
| Covered user stories | 2 (100%) |
| Total HLR | 2 (HLR-013, HLR-014) |
| Implemented HLR | 2 (100%) |
| Total LLR | 6 (013.1–013.3, 014.1–014.3) |
| Implemented LLR | 6 (100%) |
| In-scope test cases | TC-201..211 (11) + 1 REUSE-extend action-set assertion |
| TC pass | all (0 orphans) |
| TC fail | 0 |
| TC pending | 0 |
| Blocker fails | 0 |
| Full suite | 861 passed / 29 skipped / 3 xfailed / **0 failed** (893 collected, exit 0) |
| Ledger | 879 baseline + 14 = **893 EXACT** (I1 +7, I2 +5, I3 +2) |

---

## 4. Detected gaps

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | **None.** 0 blocker / 0 major / 0 minor functional gaps (`04-validation.md` §6). | Proceed to close. |

Non-blocking notes (recorded, not gaps): pre-existing `F401` in `app.py` / `change_service.py` (import lines untouched vs `febd843`); a documented bytes-vs-str annotation accepted at Inc-2 review; new CRC widgets / paste row have no dedicated `.tcss` (default Textual layout, functionally correct).

---

## 5. Bidirectional mapping

### 5.1 By user story
- **US-013** → HLR-013 → LLR-013.1 / .2 / .3 → TC-201, TC-202, TC-203, TC-204
- **US-014** → HLR-014 → LLR-014.1 / .2 / .3 → TC-205, TC-206, TC-207, TC-208, TC-209, TC-210, TC-211 + action-set REUSE-extend

### 5.2 By code file
- `s19_app/tui/operations/crc_config.py` (`read_crc_config_text`) → LLR-013.2 / .3 → TC-202, TC-204
- `s19_app/tui/screens.py` (CRC config widgets + Load handler) → LLR-013.1 / .2 / .3 → TC-201, TC-203, TC-204
- `s19_app/tui/changes/io.py` (`parse_change_document`, `DUMMY_CHANGESET_TEXT`) → LLR-014.1 / .2 → TC-206, TC-207, TC-209, TC-210, TC-211
- `s19_app/tui/services/change_service.py` (`load_text`) → LLR-014.2 → TC-208 (route)
- `s19_app/tui/screens_directionb.py` (paste `TextArea` + `ActionRequested.paste_text`) → LLR-014.1 / .2 → TC-205, TC-208
- `s19_app/tui/app.py` (`PATCH_ACTIONS_V2` + `parse_paste` router) → LLR-014.2 / .3 → TC-208, action-set assertion

### 5.3 Reconciliation notes (V-5 provisional-identifier scope, no coverage gap)
- TC-208 — the two provisional `-k` selectors (`paste_parse_routes` + `paste_then_apply`) collapsed into the single end-to-end node `test_paste_parse_then_apply_matches_file_loaded` (route-then-apply in one node — stronger).
- action-set node renamed `..._exactly_nine_...` → `..._exactly_ten_...` (planned REUSE-extend, 9→10).
- A-5 call-site line drift reconciled: `screens.py:774 → 795/801/841`; `app.py:1301 → 1336-1338`.

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-06-17-batch-13` |
| Validation verdict | **PASS** (`04-validation.md` §8) |
| LLR coverage | 6/6 (100%) |
| Write-surface gate | PASS (0 new write paths vs `febd843`) |
| Synced to Obsidian | pending (run `/dev-flow-sync` after merge) |
