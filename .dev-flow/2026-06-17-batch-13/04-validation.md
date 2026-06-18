# Phase 4 — Validation — s19_app — Batch 2026-06-17-batch-13

> Owner: qa-reviewer. Validates the Phase-3 implementation (Inc 1/2/3) of HLR-013 + HLR-014 (2 HLR / 6 LLR) against §5 (validation strategy) and the §6.5 amendments. BLUF first.

---

## 0. BLUF — Verdict: **PASS**

Batch-13 ships both surfaces with full LLR coverage and zero blocker fails.

- **Full suite: 861 passed, 29 skipped, 3 xfailed, 0 failed, exit 0** (run once, authoritative, 764.86s). `pytest --collect-only` = **893 collected** (861 + 29 + 3 = 893).
- **Ledger reconciles EXACT:** post = 879 (baseline) + 14 = **893** (I1 +7, I2 +5, I3 +2). Confirmed.
- **6/6 LLRs covered by ≥1 passing real test node** (TC-201..211 all map to a real passing node; 0 orphans).
- **A-5 surface-reachability: 7/7 story dimensions reach the SHIPPED handler call-site.** SCOPE-1 (writer-API-complete / surface-incomplete) does NOT recur.
- **Write-surface gate (LLR-014.3, F-S-03): PASS** — `git diff febd843 -- apply.py verify.py workspace.py` = **0 lines**; `emit_s19_from_mem_map` + `save_patched` symbol bodies unchanged. 0 new write paths.
- **Refactor-fidelity invariants PASS:** `MF-JSON-PARSE` on malformed paste (TC-209); delegation `call_count==1` (TC-210); parity oracle narrowed to `entries` + `{issue.code}` with `source_path=None` divergence asserted (TC-207).
- **Changeset tripwire PASS:** `examples/**/*changeset*.json` empty (git-tracked AND on-disk).
- **Frozen-engine guards PASS:** `test_engine_unchanged.py` + `test_tui_directionb.py -k tc031`.
- **Non-blocking notes only:** pre-existing `F401` in `app.py`/`change_service.py` (NOT introduced — import lines untouched vs `febd843`); a documented bytes-vs-str annotation (accepted at Inc-2 review); 2 provisional-id line-drifts reconciled below (no coverage gap). The 29 skips / 3 xfails are pre-existing (registered `slow` stress marker + standing xfails), not batch-13 regressions.

No blocker fail → no iterate-to-Phase-3. Proceed to Phase 5.

---

## 1. Full-suite result + ledger reconciliation

| Field | Value | Evidence |
|-------|-------|----------|
| Command | `python -m pytest -q` (whole suite, run once) | — |
| Result | **861 passed, 29 skipped, 3 xfailed, 0 failed, 0 error**, exit 0 | suite run, 764.86s (0:12:44) |
| Collection | **893 collected** | `pytest --collect-only -q` → "893 tests collected"; 861 + 29 + 3 = 893 |
| Baseline | 879 (b12 close, V-7) | PLAN.md Test ledger |
| Delta | +14 | I1 +7, I2 +5, I3 +2 |

**Signed-balance test ledger (`post = base − D + A`):**

| base | − D | + A | = post | actual collected | passed / skip / xfail | reconciles? |
|------|-----|-----|--------|------------------|------------------------|-------------|
| 879 | 0 | 14 | **893** | **893** | 861 / 29 / 3 | **yes (EXACT)** |

**Per-increment signed check:**

| Increment | Added | Removed | Running collected | Signed check |
|-----------|-------|---------|-------------------|--------------|
| Baseline (febd843 / b12 close) | — | — | 879 | V-7 confirmed |
| Inc 1 (US-013) | +7 | 0 | 886 | 879 − 0 + 7 = 886 ✓ |
| Inc 2 (US-014 data) | +5 | 0 | 891 | 886 − 0 + 5 = 891 ✓ |
| Inc 3 (US-014 UI) | +2 (TC-205/208; action-pin renamed = REUSE net 0) | 0 | 893 | 891 − 0 + 2 = 893 ✓ |
| **Post** | **+14** | **0** | **893** | **879 + 14 = 893 EXACT** |

Collection count (893) == ledger post (893) == suite total (861+29+3 = 893). No discrepancy. The 29 skips are the registered `slow` stress-smoke block (skipped by default config); the 3 xfails are standing expected-failures — both pre-existing, neither introduced by batch-13.

---

## 2. Per-LLR pass/fail table (real node ids + evidence)

> Provisional TC-2xx ids reconciled against the real tree via `pytest --collect-only`. All nodes verified to EXIST on disk and PASS (not signed off from intent).

| HLR/LLR | Method | Real test node id(s) | TC | Result | Evidence |
|---------|--------|----------------------|----|--------|----------|
| **HLR-013** | test (int) | `test_tui_crc_surface.py` (4 nodes) + `test_crc_config.py::test_read_crc_config_text_*` (4) | TC-201..204 | **pass** | 24 nodes pass; CRC run path still consumes `parse_crc_config(TextArea.text)` (run path unchanged) |
| LLR-013.1 — path Input + Load button placement | test (int) | `test_crc_config_load_widgets_present_and_toggle` | TC-201 | **pass** | widgets `#operation_config_path` + `#operation_config_load` present + display-toggle on/off CRC row |
| LLR-013.2 — resolve+cap+read raw text (no parse) | test (unit)+(int) | `test_read_crc_config_text_returns_raw_text_without_parsing`, `..._over_cap_collects_one_error_without_reading`, `..._returns_unparsed_invalid_json`; `test_crc_config_load_ok_populates_editor_via_handler` | TC-202, TC-203 | **pass** | raw str returned, no parse; byte-equal load THROUGH `on_button_pressed`→`_load_config_from_path` (screens.py:795/801/841) |
| LLR-013.3 — fault surfaces + no run; dummy stays | test (int) | `test_crc_config_load_fault_surfaces_error_and_no_check`, `test_crc_config_error_surfaces_error_and_no_match`; `test_read_crc_config_text_unresolvable_path_collects_one_error` | TC-204 | **pass** | fault → 1 error, editor unchanged, 0 checks; mount `#operation_config.text == DUMMY_CONFIG_TEXT` |
| **HLR-014** | test (int) | `test_tui_patch_editor_v2.py` (3 new) + `test_changes_schema.py` (5 new) | TC-205..211 | **pass** | paste/parse/apply + parity/malformed/delegation/tripwire all pass; `PATCH_ACTIONS_V2` = 10 |
| LLR-014.1 — `DUMMY_CHANGESET_TEXT` pre-loaded ref | test (int)+(unit) | `test_paste_textarea_preloads_dummy_changeset`; `test_dummy_changeset_parses`; `test_no_changeset_under_examples` | TC-205, TC-206, TC-211 | **pass** | mount text == dummy (rstrip tolerance); dummy parses kind=change, ≥1 entry, 0 ERROR; tripwire empty |
| LLR-014.2 — paste text→document parse seam | test (unit)+(int) | `test_parse_from_string_matches_file_read`, `test_parse_malformed_json_emits_mf_json_parse`, `test_read_change_document_delegates_to_parse`; `test_paste_parse_then_apply_matches_file_loaded` (route half) | TC-207, TC-209, TC-210, TC-208 | **pass** | entries+`{code}` parity, `source_path` divergence asserted; `MF-JSON-PARSE`; `call_count==1`; `parse_paste` routes to `load_text` (app.py:1336-1338) |
| LLR-014.3 — parsed doc feeds existing apply/containment | test (int)+inspection | `test_paste_parse_then_apply_matches_file_loaded` (apply+save-back half) + STANDING write-surface diff gate | TC-208 + gate | **pass** | identical apply outcome + save-back prompt name identity (F-A-06); `git diff febd843` apply/verify/workspace = 0 lines |

**Result: 6/6 LLRs PASS · 2/2 HLRs PASS · LLR coverage = 100% · 0 blocker fails.**

---

## 3. TC reconciliation table

> Every in-scope spec TC (TC-201..211) maps to exactly one real passing node. 0 orphans. Two provisional ids merged/renamed by the implementer (recorded, not a gap).

| Spec TC | Provisional id (§5.2) | Real passing node | Status |
|---------|------------------------|-------------------|--------|
| TC-201 | `crc_config_load_widgets` | `test_crc_config_load_widgets_present_and_toggle` | mapped ✓ |
| TC-202 | `read_crc_config_text` (unit) | `test_read_crc_config_text_returns_raw_text_without_parsing` (+3 sibling unit cases) | mapped ✓ |
| TC-203 | `crc_config_load_ok` | `test_crc_config_load_ok_populates_editor_via_handler` | mapped ✓ |
| TC-204 | `crc_config_load_fault` | `test_crc_config_load_fault_surfaces_error_and_no_check` (+ `..._error_surfaces_error_and_no_match`) | mapped ✓ |
| TC-205 | `dummy_changeset_preload` | `test_paste_textarea_preloads_dummy_changeset` | mapped ✓ |
| TC-206 | `dummy_changeset_parses` | `test_dummy_changeset_parses` | mapped ✓ |
| TC-207 | `parse_from_string` | `test_parse_from_string_matches_file_read` | mapped ✓ |
| TC-208 | `paste_parse_routes` + `paste_then_apply` | `test_paste_parse_then_apply_matches_file_loaded` (route+apply merged into one node) | mapped ✓ (2→1 merge) |
| TC-209 | `parse_malformed_json` | `test_parse_malformed_json_emits_mf_json_parse` | mapped ✓ |
| TC-210 | `read_delegates_to_parse` | `test_read_change_document_delegates_to_parse` | mapped ✓ |
| TC-211 | `no_changeset_under_examples` | `test_no_changeset_under_examples` | mapped ✓ |
| action-set | `..._exactly_nine_v2_actions` | `test_action_routing_pins_exactly_ten_v2_actions` (REUSE-extend, renamed 9→10) | mapped ✓ |

**Orphans: 0.** Every TC-2xx → exactly one real passing node. The only structural deltas are (a) TC-208's two provisional `-k` selectors collapsed into one node that drives route-then-apply end-to-end (stronger, not weaker), and (b) the action-set assertion renamed `nine→ten` (the planned REUSE-extend). Both trace to named LLRs (014.2/014.3); no extra unaccounted node.

---

## 4. Surface-reachability matrix (A-5 / SCOPE-1 control)

> For each input dimension named in a source user story, ≥1 TC exercises it THROUGH the shipped handler call-site (not only via direct service kwargs). Handler `file:line` grep-verified against the live tree.

| # | Dimension (US story) | Shipped handler call-site (grep-verified `file:line`) | Covering TC | Through-handler? |
|---|----------------------|--------------------------------------------------------|-------------|------------------|
| US-013-a | Valid config path → `#operation_config` populated | `on_button_pressed` → `_load_config_from_path` → `read_crc_config_text` — **screens.py:795 / 801 / 841** | TC-203 | **Y** |
| US-013-b | Invalid/irresolvable/over-cap → error + no check | same handler — **screens.py:801/841** | TC-204 | **Y** |
| US-013-c | No-file → dummy stays | `OperationsScreen.compose` mount (`TextArea(DUMMY_CONFIG_TEXT, id="operation_config")`) | TC-204 (mount) | **Y** |
| US-014-a | Patch Editor mount → dummy pre-loaded | `PatchEditorPanel.compose` paste `TextArea` `#patch_paste_text` — screens_directionb.py | TC-205 | **Y** |
| US-014-b | Paste valid → parse via panel action → document | `ActionRequested(action="parse_paste", paste_text=…)` → router `elif` → `service.load_text` — **app.py:1336-1338** | TC-208 | **Y** |
| US-014-c | Paste malformed → collect-don't-abort surfaces faults | same router → `_report_change_result` — **app.py:1336-1338** | TC-208 (+ TC-207/TC-209 at seam) | **Y** |
| US-014-d | Parsed doc → existing apply path reachable | `apply_doc` router (UNCHANGED) — app.py:1335 region | TC-208 (apply assert) | **Y** |

**7/7 dimensions Y (through-handler). SCOPE-1 does NOT recur.** TC-208 drives the actual panel→`ActionRequested(paste_text)`→router→`load_text` path (not a direct `load_text` kwarg call), and additionally drives `apply_doc` on the resulting document, asserting save-back prompt-name identity vs a file-loaded doc. The b11 failure mode — a writer fully tested via direct kwargs while the handler passes empty fields — cannot recur here because the covering TC enters through the shipped call-site. TC-207 additionally pins service-level parse-parity so the through-handler path cannot silently diverge.

**Provisional-id note (no coverage gap):** §5.2.1 cited `screens.py:774` (US-013) and `app.py:1301` (US-014) provisionally; the real call-sites are screens.py:795/801/841 and app.py:1336-1338 — line drift only (V-5 provisional-identifier scope), reconciled here. Coverage unchanged.

---

## 5. Inspection results (write-surface gate, refactor-fidelity, tripwire, frozen guard)

### 5.1 Standing write-surface gate (LLR-014.3, F-S-03) — **PASS (HARD gate)**

Baseline = **`febd843`** (real batch-13 base / PR #17 merge / `origin/main` tip), NOT the stale local `main` ref `ec453a2` (§6.5 Amendment A-1).

| Check | Command | Result |
|-------|---------|--------|
| 3-file write surface unchanged | `git diff --stat febd843 -- s19_app/tui/changes/apply.py s19_app/tui/changes/verify.py s19_app/tui/workspace.py` | **empty (0 lines)** ✓ |
| `emit_s19_from_mem_map` body unchanged | `git diff febd843 -- io.py` hunk inspection | io.py diff hunks confined to `__all__` + new `parse_change_document` + `read_change_document` refactor (hunks end ~line 563); `emit_s19_from_mem_map` (io.py:1300) NOT in any hunk ✓ |
| `save_patched` body unchanged | `git diff febd843 -- change_service.py` hunk inspection | diff = import line + new `load_text` at :630 only; `save_patched` (:807) NOT in any hunk ✓ |

**0 new write code paths.** The two files Inc 2 edits (io.py, change_service.py) changed ONLY in the parse seam / `load_text`, never in the emit/save symbols.

### 5.2 Refactor-fidelity invariants (inspections) — **PASS**

| Invariant | Where asserted | Result |
|-----------|----------------|--------|
| `MF-JSON-PARSE` on malformed paste (3-exception catch re-homed) | TC-209 `test_parse_malformed_json_emits_mf_json_parse` (test_changes_schema.py:594-605) | ✓ malformed string → `MF-JSON-PARSE`, 0 raises |
| Delegation `call_count==1` (refactor = delegation, not duplication) | TC-210 `test_read_change_document_delegates_to_parse` (:641 `parse_spy.call_count == 1`) | ✓ |
| Parity oracle = `entries` + `{issue.code}` ONLY (narrowed) | TC-207 `test_parse_from_string_matches_file_read` (:582-583) | ✓ whole-doc `==` NOT used |
| `source_path=None` on string seam | TC-207 (:588 `from_string.source_path is None`; :589 `from_file.source_path is not None`); also :553/:645 | ✓ divergence asserted; file read re-stamps `source_path` |

### 5.3 Changeset tripwire (TC-211, F-S-04) — **PASS**

| Check | Result |
|-------|--------|
| `git ls-files 'examples/**changeset**'` | empty ✓ |
| `pathlib.Path('examples').glob('**/*changeset*.json')` (on-disk) | `[]` ✓ |
| `test_no_changeset_under_examples` | passes ✓ |

### 5.4 Frozen-engine guard — **PASS**

| Guard | Result |
|-------|--------|
| `test_engine_unchanged.py` | 1 passed (in mapped run + full suite) ✓ |
| `test_tui_directionb.py -k tc031` | 3 passed ✓ |

All 6 batch-13 production files are outside both `_ENGINE_PATHS` guard lists (RK-C re-confirmed); the parse seam landed in non-frozen `changes/io.py`, the CRC reader in non-frozen `operations/crc_config.py` — both correct per the batch-10 placement lesson.

---

## 6. Gaps detected

| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| — | — | **None.** 0 blocker / 0 major / 0 minor functional gaps. | — | Proceed to Phase 5. |

### Notes (non-blocking, recorded for the post-mortem)

1. **Pre-existing `F401` (NOT introduced).** `app.py` carries 6 pre-existing `F401` (unused `workspace.PROJECT_DATA_EXTENSIONS`/`PROJECT_PRIMARY_DATA_EXTENSIONS`/`S19_EXTENSIONS` etc.); `change_service.py` carries 1 (`typing.List`). Verified out-of-scope: `git diff febd843` shows neither import line is touched by batch-13. Left surgical (engineering rule 3). Out of scope for this batch.
2. **bytes-vs-str annotation (documented, accepted).** Flagged at Inc-2 code review as acceptable (docstring documents it); not a correctness fault. No action.
3. **Provisional-id reconciliations (V-5, no coverage gap):** (a) TC-208's two provisional `-k` selectors (`paste_parse_routes` + `paste_then_apply`) collapsed into the single node `test_paste_parse_then_apply_matches_file_loaded` — stronger end-to-end coverage; (b) action-set node renamed `..._exactly_nine_...` → `..._exactly_ten_...` (planned REUSE-extend); (c) A-5 call-site line drift (screens.py:774→795/801/841; app.py:1301→1336). All recorded in §3/§4.
4. **No new engine math → no RK-3-style honest carry expected, and none found.** Batch-13 is two existing-substrate TUI surfaces; the contained emit / verify / save-back path is reused verbatim (write-surface gate confirms 0 new write paths). No numerical/device-vector carry.
5. **29 skips / 3 xfails are pre-existing, not regressions.** The `ss` block at ~80% of the run is the registered `slow` stress-smoke marker (skipped by default config); the 3 `x` are standing expected-failures. Neither was introduced by batch-13.
6. **Visual polish unspecified (Inc-1/Inc-3 risk, deferred).** New CRC config widgets and the paste row have no dedicated `.tcss` (default Textual layout); functionally correct (tests assert via `.display` / `run_test`), live-terminal visual not inspected. No LLR requires it; deferred, non-blocking.

---

## 7. Evidence checklist — qa-reviewer (full)

- [✓] **Acceptance criteria use Given/When/Then** — §3/§4 of 01-requirements.md use EARS (When/While/If…then…shall), the IEEE-830 normative equivalent; §2.6 ACs are Given/When/Then. Verified in source.
- [✓] **Test cases have explicit Expected, not vague "works"** — each LLR row carries a numeric pass threshold (byte-equal, `call_count==1`, exactly-1-error, 0 changed lines). §2 table.
- [✓] **Edge cases include empty, boundary, invalid, error** — empty path (TC-204), over-cap boundary (`test_read_crc_config_text_over_cap...`), invalid JSON (TC-202 unparsed / TC-209 malformed→MF-JSON-PARSE), error/fault surface (TC-204).
- [✓] **Regression checklist exists** — frozen guards (test_engine_unchanged + tc031), full-suite 861 passed / 0 failed, CRC suite + Patch Editor v2 suite 0 regressions (increment notes §4). §5.4.
- [✓] **Exit criteria stated** — §5.3 batch acceptance criteria in 01-requirements.md (100% LLR coverage, 0 regressions, gate rows); all met. §0 BLUF.
- [✓] **No real PII / secrets** — `DUMMY_CHANGESET_TEXT`/`DUMMY_CONFIG_TEXT` are FAKE-valued; changeset tripwire empty (§5.3); JSON-never-in-repo honored.
- [✓] **Test results section reflects an ACTUAL run** — full suite executed once (861 passed / 29 skipped / 3 xfailed, exit 0, 764.86s); 21 mapped nodes + frozen guards executed and confirmed passing; not signed off from intent.

---

## 8. Phase-4 verdict

**PASS.** 0 blocker fails → no iterate-to-Phase-3. All 6 LLRs covered by passing real nodes; 861 passed / 0 failed (893 collected); ledger EXACT; A-5 7/7 through-handler; write-surface gate 0 lines vs `febd843`; refactor-fidelity + tripwire + frozen guards all hold. Notes in §6 are non-blocking and pre-existing/out-of-scope. **Proceed to Phase 5 (post-mortem).**
