# Traceability Matrix — s19_app — Batch 2026-06-13-batch-10

> Full chain: **User Story → HLR → LLR → Test Case → File:line**.
> US-008 (Intel HEX writer) and US-009 (verify-on-save). 5 HLR, 14 LLR, TC-001..013.
> All `File:line` anchors below were grep-verified against the current worktree tree at HEAD on 2026-06-14 (**41 anchors verified — see §5.3**). Test-node ids are the IMPLEMENTED node ids (not the provisional Phase-1 spec ids); the spec-TC → implemented-node mapping follows the §1 matrix of `04-validation.md`. Status is taken from `04-validation.md` (all PASS).

---

## 1. Master table

Legend — TC col carries the spec id (TC-NNN); the implemented node id is in the File:line cell. `File:line` cites BOTH the implementation site and the verifying test site.

| US | HLR | LLR | TC | File:line (impl → test) | Status | Notes |
|----|-----|-----|----|--------------------------|--------|-------|
| US-008 | HLR-001 | LLR-001.1 | TC-001 | impl `s19_app/tui/changes/io.py:1424` (`emit_intel_hex_from_mem_map`, signature `(mem_map, ranges) -> str`) → test `tests/test_hex_emit.py:76` (`test_low_address_roundtrip`, ×3 params) | pass | Purity probe P-1: 0 `textual` in io.py; static-import-graph guard `tests/test_checks_engine.py:400` green |
| US-008 | HLR-001 | LLR-001.2 | TC-002 | impl `s19_app/tui/changes/io.py:1497` (`_intel_hex_record`, checksum at `:1529`) + `io.py:1421` (`HEX_DATA_BYTES_PER_RECORD = 16`) → test `tests/test_hex_emit.py:83` (`test_data_records_max_16_bytes_and_checksum`) | pass | Re-read oracle `IntelHexFile(...).get_errors()` empty (`s19_app/hexfile.py:173`); ≤16 data bytes/record |
| US-008 | HLR-001 | LLR-001.3 | TC-003 | impl `s19_app/tui/changes/io.py:1488-1490` (ELA emit on upper-16 change) → test `tests/test_hex_emit.py:103` (`test_ela_high_address_roundtrip`) + `:121` (`test_ela_record_emitted_per_upper16_change`) | pass | Parser oracle `sum(r.record_type==0x04 for r in IntelHexFile(written).records) >= 1` (base 0x08040000); 2nd test asserts `>= 2` |
| US-008 | HLR-001 | LLR-001.4 | TC-004 | impl `s19_app/tui/changes/io.py:1493-1494` (single EOF + trailing newline) → test `tests/test_hex_emit.py:138` (`test_empty_mem_map_emits_eof_only`) + `:150` (`test_output_terminates_with_single_eof`) + `:161` (`test_public_example_roundtrips_as_hex`) | pass | Empty input → `:00000001FF` only; round-trip `IntelHexFile(written).memory == input` 100% |
| US-008 | HLR-002 | LLR-002.1 | TC-005 | impl `s19_app/tui/changes/apply.py:574` (`save_patched_image`), HEX branch via `_SAVE_BACK_EMITTERS["hex"]` `apply.py:101`, parametric sanitizer `apply.py:711` (`_sanitize_s19_filename(..., suffix=)`) → test `tests/test_changes_apply.py:424` (`test_hex_save_writes_hex_file_that_reparses_to_post_apply_map`) + `:453` (`test_hex_save_forces_hex_suffix_when_name_lacks_it`) + `:472` (`test_s19_save_still_forces_s19_suffix`) + `:499` (`test_hex_save_adversarial_filenames_contained_or_refused`, ×4) | pass | One `.hex` under `.s19tool/workarea/`; 2-tuple return `(Optional[Path], List[ValidationIssue])` PRESERVED (`apply.py:581`); 4 adversarial names contained-or-refused with `MF_WRITE_CONTAINMENT` |
| US-008 | HLR-002 | LLR-002.2 | TC-006 | impl `s19_app/tui/changes/apply.py:654-665` (`CHG_HEX_SAVE_UNSUPPORTED` now refuses only non-{s19,hex}; defined `apply.py:94`, in `__all__` `apply.py:84`) → test `tests/test_changes_apply.py:395` (`test_save_back_unsupported_source_refused_with_clear_issue`) | pass | `"hex"` → 0 such issues; `"mac"` → 1 issue + 0 writes (extended pre-existing TC-006 test, not a brand-new node) |
| US-008 | HLR-002 | LLR-002.3 | TC-007 | impl save-back suffix made format-aware in the TUI suggest path (`s19_app/tui/app.py`) + service forwards `file_type` (`s19_app/tui/services/change_service.py:851`) → test `tests/test_tui_patch_editor_v2.py:731` (`test_save_back_suggestion_is_format_aware`) | pass | Coverage-location shift: realized at the TUI layer, not the service layer (DEV-4). HEX → `*-patched.hex`; S19 default stays `.s19` |
| US-009 | HLR-003 | LLR-003.1 | TC-008 | impl `s19_app/tui/changes/verify.py:119` (`verify_written_image`) + `:81` (`_reread_mem_map`, parser selection by `file_type`) → test `tests/test_verify_on_save.py:82` (`test_identity_write_is_verified`, ×2 hex/s19) + `:135` (`test_unsupported_file_type_raises`) | pass | `IntelHexFile.memory` (`hexfile.py:25`) / `S19File.get_memory_map()` re-read; `"mac"` → `ValueError`; purity probe P-2: 0 `textual` in verify.py |
| US-009 | HLR-003 | LLR-003.2 | TC-009 | impl `s19_app/tui/changes/verify.py:164-165` (`runs, stats = diff_mem_maps(intended, reread)`; status verified iff `not runs`) → test `tests/test_verify_on_save.py:96` (`test_mutated_byte_is_mismatch_changed`, ×2) + `:115` (`test_dropped_byte_is_mismatch_only_a`, ×2) | pass | MUTATION → one `changed` run len 1; DROP → one `only_a` run len 1; property reads on `DiffRun.length` (`compare.py:138`), `DiffRun` constructed `(start,end,kind)` (`compare.py:100`) |
| US-009 | HLR-003 | LLR-003.3 | TC-010 | impl `s19_app/tui/services/change_service.py:867-869` (post-save `verify_written_image`, stamps `last_summary.verify_result` — C-10 carrier; 2-tuple unchanged) → test `tests/test_changes_apply.py:530` (`test_verify_written_hex_image_is_verified`) + `:549` (`test_verify_on_dropped_byte_is_mismatch_file_kept`) + `tests/test_change_service.py:242` (`test_hex_save_stamps_verified_result_on_summary`) + `:271` (`test_refused_save_leaves_verify_result_none`) | pass | Collect-don't-abort: injected DROP → file kept + `mismatch` + one `only_a` len 1; refused save → `verify_result` stays `None` |
| US-009 | HLR-004 | LLR-004.1 | TC-011a | impl `s19_app/tui/app.py:1420` (`_surface_verify_result`), quiet path `app.py:1464` (`Saved + verified: {name}`) → test `tests/test_tui_patch_editor_v2.py:761` (`test_verify_quiet_pass_on_faithful_hex_save`) | pass | One "Saved + verified" status line; 0 error notices; real round-trip `verified` (test-realized demo) |
| US-009 | HLR-004 | LLR-004.2 | TC-011b | impl `s19_app/tui/app.py:1466-1474` (mismatch notice, `severity="error"`) + `app.py:1476` (`_verify_mismatch_summary` over `DIFF_KIND_DOMAIN`, `compare.py:53`) → test `tests/test_tui_patch_editor_v2.py:808` (`test_verify_loud_mismatch_notice`) | pass | Notice names file + `changed 1 run / 1 byte`; file kept; counts/addresses only — no raw byte leak (F-S-05) |
| US-008,US-009 | HLR-005 | LLR-005.1 | TC-012 | impl `s19_app/tui/screens.py:562` (`id="operations_buttons"`; `load_buttons` shared id eliminated — `.modal-buttons` class kept, `screens.py:42`) → test `tests/test_tui_operations_view.py:390` (`test_operations_button_row_has_screen_unique_id`) | pass | Probe P-3: `rg 'id="load_buttons"' screens.py` → 0 matches (was 6); `#load_buttons` query → 0 |
| US-008,US-009 | HLR-005 | LLR-005.2 | TC-013 | impl `s19_app/tui/screens.py:631` (`operation_resolver(operation_id)` inside narrow `try`) + `:632` (`except KeyError`), `.execute(...)` outside the catch → test `tests/test_tui_operations_view.py:296` (`test_execute_internal_keyerror_not_masked_as_unknown_operation`) | pass | M-3: resolver miss → 1 "unknown operation" status; `.execute`-internal `KeyError` propagates (raised=True), NOT masked. Seam `operation_service.operation_resolver` (`operation_service.py:35`) |

**Per-requirement verdict (from `04-validation.md` §1): 5/5 HLR PASS, 14/14 LLR PASS, 0 fails, 0 skips. 35/35 targeted node-results pass.**

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 2 (US-008, US-009) |
| Covered user stories | 2 (100%) |
| Total HLR | 5 |
| Implemented HLR | 5 (100%) |
| Total LLR | 14 |
| Implemented LLR | 14 (100%) |
| Test cases (spec) | 13 (TC-001..013) |
| TC pass | 13 (100%) |
| TC fail | 0 |
| TC pending | 0 |
| Targeted node-results (implemented) | 35 passed / 35 |
| Collection delta | 782 → 816 (+34 new nodes, D=0, no regression) |

---

## 3. Detected gaps

> No coverage gaps and no functional failures. Every entry below is a DEV-class doc-reconciliation or an informative note from `04-validation.md` §5 — none is a blocker. Status reflects Phase-6 disposition.

| ID | Type | Description | Status / action |
|----|------|-------------|-----------------|
| DEV-1 | V-5 rename | Spec `test_operations.py -k "keyerror_scope..."` (TC-013) → implemented `tests/test_tui_operations_view.py:296::test_execute_internal_keyerror_not_masked_as_unknown_operation`. | RESOLVED in Phase 6 (matrix uses the implemented node id; sibling agent applies the reconciliation concurrently). |
| DEV-2 | V-5 rename | Spec `test_hex_emit.py -k "data_record/ela/roundtrip"` → descriptive function names (`tests/test_hex_emit.py:76,83,103,121,138,150,161`); file path matched. | RESOLVED in Phase 6. |
| DEV-3 | V-5 rename | Spec `test_verify_on_save.py -k "reread/verified or mismatch"` → `test_identity_write_is_verified` / `test_mutated_byte_is_mismatch_changed` / `test_dropped_byte_is_mismatch_only_a` (parametrized hex/s19). | RESOLVED in Phase 6. |
| DEV-4 | V-5 rename + coverage-shift | LLR-002.3 suffix coverage realized at the TUI layer (`tests/test_tui_patch_editor_v2.py:731::test_save_back_suggestion_is_format_aware`), not the service layer. The two service-layer nodes that landed (`test_change_service.py:242,271`) cover LLR-003.3 (verify-result stamping) instead. Threshold still met. | RESOLVED in Phase 6 (matrix records the coverage-location shift in the LLR-002.3 / LLR-003.3 rows). |
| DEV-5 | V-5 doc note | In-file TC labels lag the spec table (`test_tui_operations_view.py` docstring TC-010..012; `test_changes_apply.py` header TC-009..013 — older engine numbering). Spec §5.2 ids (TC-005..013) map per §1. | RESOLVED in Phase 6 (cosmetic; matrix is the authority on the TC mapping). |
| DEV-6 | V-5 doc note | `test_hex_emit.py` module docstring says "D-A=(a) R2-relocated" — inconsistent; D-A resolved to **(c)** per H-5. Relocation outcome (io.py) correct; only the option-letter label is wrong. | RESOLVED in Phase 6 (cosmetic typo; sibling agent corrects the docstring). |
| DEV-7 | Post-mortem action (CARRIED) | The 4th guard family (engine-frozen / no-diff-vs-main) was missed by the Phase-1/2 census, forcing the I1→io.py reversal (R2/H-5). The V-3 census-completeness probe set must permanently include `rg -n "_ENGINE_PATHS\|no_diff_vs_main\|engine_modules_unchanged" tests/`. | CARRIED to Phase 5 post-mortem as a process-rule extension (template widening). Not a Phase-6 doc edit. |
| DEV-8 | Tidy | `emit_intel_hex_from_mem_map` is NOT re-exported from `s19_app/tui/changes/__init__.py`, whereas its precedent `emit_s19_from_mem_map` IS. Tests import directly from `...changes.io`, so functionally inert. | RESOLVED in Phase 6 (low-priority tidy; sibling agent adds the re-export for symmetry). |
| DEV-9 | Measure (INFORMATIVE) | Byte-stability is a recorded MEASURE (`record_property`), not a gate — by design (canonicalization expected). No `emit(parse(file))==file` byte-identity assertion exists (`tests/test_hex_emit.py:174::test_byte_stability_measure`). | INFORMATIVE — no action required; recorded per spec §5. |

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | US-008 / HLR-001 | Intel HEX **writer** added — `emit_intel_hex_from_mem_map` (`io.py:1424`), the symmetric counterpart to `emit_s19_from_mem_map` (`io.py:1300`). The repo could read HEX but never write it. |
| new | US-008 / HLR-002 | HEX save-back path: `save_patched_image` HEX branch via `_SAVE_BACK_EMITTERS` (`apply.py:101`); `_sanitize_s19_filename` gained a parametric `suffix` arg (`apply.py:711`). |
| new | US-009 / HLR-003 | `verify.py` module (NEW): `verify_written_image` + `VerifyResult` (`verify.py:35,119`); first downstream consumer of the batch-09 `compare.diff_mem_maps` engine (`compare.py:272`). |
| new | US-009 / HLR-004 | Hybrid verify surface in the TUI: `_surface_verify_result` / `_verify_mismatch_summary` (`app.py:1420,1476`). |
| modified | HLR-002 refusal | `CHG_HEX_SAVE_UNSUPPORTED` (`apply.py:94`) retired for `"hex"` sources; still refuses `"mac"` and other non-{s19,hex}. Supersedes the batch-07 D-1 / F-A-05 S19-only save-back decision for HEX. |
| modified | C-10 carrier | `ChangeService.last_summary` gained `verify_result` (`change_service.py:869`); `save_patched_image`'s 2-tuple return preserved unchanged (back-compatible carrier, M-1) — 0 caller/test unpack edits. |
| folded | HLR-005 hygiene | `load_buttons` shared widget id eliminated across the six modal screens → `operations_buttons` (`screens.py:562`); `OperationsScreen._execute_selected` `except KeyError` narrowed to the resolver-lookup only (`screens.py:631-632`). |
| reused (unchanged) | compare engine | `compare.py` (batch-09) consumed as-is; `hexfile.py` reader kept PRISTINE (engine-frozen — `git diff main -- hexfile.py` empty). |
| design reversal | D-A / G-1 (H-5) | Emitter location reversed from `hexfile.py` (option a) to `tui/changes/io.py` (option c) mid-Phase-3, forced by the engine-frozen guard family (operator R2, 2026-06-14). |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-008** → HLR-001 (emitter), HLR-002 (save-back), HLR-005 (folded hygiene) → LLR-001.1..001.4, LLR-002.1..002.3, LLR-005.1/005.2 → TC-001..007, TC-012/013
- **US-009** → HLR-003 (verify engine), HLR-004 (surfacing), HLR-005 (folded hygiene) → LLR-003.1..003.3, LLR-004.1/004.2, LLR-005.1/005.2 → TC-008..011b, TC-012/013

### 5.2 By code file
- `s19_app/tui/changes/io.py` → LLR-001.1, LLR-001.2, LLR-001.3, LLR-001.4 → TC-001..004 (`tests/test_hex_emit.py`)
- `s19_app/tui/changes/apply.py` → LLR-002.1, LLR-002.2 → TC-005, TC-006 (`tests/test_changes_apply.py`)
- `s19_app/tui/changes/verify.py` → LLR-003.1, LLR-003.2 → TC-008, TC-009 (`tests/test_verify_on_save.py`)
- `s19_app/tui/services/change_service.py` → LLR-002.3 (forwarding), LLR-003.3 → TC-007, TC-010 (`tests/test_change_service.py`, `tests/test_changes_apply.py`)
- `s19_app/tui/app.py` → LLR-002.3 (suffix suggest), LLR-004.1, LLR-004.2 → TC-007, TC-011a/b (`tests/test_tui_patch_editor_v2.py`)
- `s19_app/tui/screens.py` → LLR-005.1, LLR-005.2 → TC-012, TC-013 (`tests/test_tui_operations_view.py`)
- `s19_app/compare.py` (batch-09, reused unchanged) → consumed by LLR-003.2 via `diff_mem_maps` (`compare.py:272`)
- `s19_app/hexfile.py` (engine-frozen, reused as round-trip oracle/reader) → consumed by LLR-001.* / LLR-003.1

### 5.3 Anchor verification ledger
All `File:line` anchors in §1 / §4 / §5.2 were grep-verified at HEAD on 2026-06-14. **41 anchors verified:**
- Implementation symbols (15): `emit_intel_hex_from_mem_map` io.py:1424, `_intel_hex_record` io.py:1497, `HEX_DATA_BYTES_PER_RECORD` io.py:1421, `emit_s19_from_mem_map` io.py:1300, `_s19_record` io.py:1372, `save_patched_image` apply.py:574 (return apply.py:581), `_SAVE_BACK_EMITTERS["hex"]` apply.py:101, `_sanitize_s19_filename` apply.py:711, `CHG_HEX_SAVE_UNSUPPORTED` apply.py:94, `verify_written_image` verify.py:119, `VerifyResult` verify.py:35, `_reread_mem_map` verify.py:81, verify diff call verify.py:164-165, `verify_result` stamp change_service.py:867-869, `_surface_verify_result`/`_verify_mismatch_summary` app.py:1420/1476.
- Reused-engine symbols (6): `diff_mem_maps` compare.py:272, `DiffRun` compare.py:100, `DiffRun.length` compare.py:138, `DiffStats` compare.py:150, `DIFF_KIND_DOMAIN` compare.py:53, `IntelHexFile` hexfile.py:20 (`.memory` :25, `.get_errors` :173, `.get_ranges` :176).
- Hygiene symbols (3): `id="operations_buttons"` screens.py:562, `operation_resolver` call screens.py:631 (`except KeyError` :632), `operation_service.operation_resolver` seam operation_service.py:35.
- Test nodes (17): `tests/test_hex_emit.py` 76/83/103/121/138/150/161/174; `tests/test_verify_on_save.py` 82/96/115/135; `tests/test_changes_apply.py` 395/424/453/472/499/530/549; `tests/test_change_service.py` 242/271; `tests/test_tui_patch_editor_v2.py` 731/761/808; `tests/test_tui_operations_view.py` 296/390.
- Absence checks: `rg 'id="load_buttons"' screens.py` → 0 matches (confirms LLR-005.1 retirement).

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-06-13-batch-10` |
| Closing date | `2026-06-14` |
| Iterations per phase | P1: 3 · P2: 1 · P3: 4 increments (I1..I4, incl. I1→io.py R2 reversal) · P4: 1 · P5: 1 · P6: 1 |
| Validation passed | yes (5/5 HLR, 14/14 LLR PASS; lean 763/0, full 784/0; collection 816 reconciled exact) |
| Synced to Obsidian | no |
