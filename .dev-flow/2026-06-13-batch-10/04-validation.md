# Validation Report — s19_app — Batch 2026-06-13-batch-10

> Phase 4 (Validation) of the dev-flow V-model. Executes §5 of `01-requirements.md`.
> Author: qa-reviewer. Date: 2026-06-14. Worktree branch: `claude/batch-10`.
> Regime: Win 11 Pro 10.0.26200, Python 3.14.x, OneDrive-synced worktree.
>
> **Run-ownership (A-6):** the orchestrator runs the FULL suite (incl. slow) and the lean suite SEPARATELY. This report owns the **per-TC targeted matrix** + **all inspections** only. Lean/full-suite §5.3 rows are left ORCHESTRATOR-OWNED.
>
> **V-5 note:** Phase-1 TC node ids were PROVISIONAL. The implemented test names differ; the mapping is recorded as DEV-class doc-reconciliation notes (NOT failures) in the deviations register below.

---

## 1. Per-requirement pass/fail matrix

Legend: **Result** reflects the qa-reviewer's targeted run of the exact implemented node id (commands §1.1).

| Req | LLR | TC (spec) | Implemented node id | Result | Evidence |
|-----|-----|-----------|---------------------|--------|----------|
| HLR-001 | — | TC-001..004 | `test_hex_emit.py` (10 nodes) | **PASS** | round-trip via `IntelHexFile`; 10 passed 0.43s |
| HLR-001 | LLR-001.1 | TC-001 | `test_low_address_roundtrip` (×3 params) | **PASS** | purity P-1 (0 textual in io.py) + signature `(mem_map, ranges)->str` |
| HLR-001 | LLR-001.2 | TC-002 | `test_data_records_max_16_bytes_and_checksum` | **PASS** | `byte_count <= HEX_DATA_BYTES_PER_RECORD`; `get_errors()==[]` |
| HLR-001 | LLR-001.3 | TC-003 | `test_ela_high_address_roundtrip`, `test_ela_record_emitted_per_upper16_change` | **PASS** | ELA oracle `sum(r.record_type==0x04 for r in reread.records)>=1` (base 0x08040000 ≥ 0x10000); 2nd test asserts `>=2` |
| HLR-001 | LLR-001.4 | TC-004 | `test_empty_mem_map_emits_eof_only`, `test_output_terminates_with_single_eof`, `test_public_example_roundtrips_as_hex` | **PASS** | empty→`:00000001FF` only; single trailing EOF; round-trip equality 100% |
| HLR-002 | — | TC-005..007 | `test_changes_apply.py` + `test_change_service.py` | **PASS** | HEX save-back; 10+2 passed |
| HLR-002 | LLR-002.1 | TC-005 | `test_hex_save_writes_hex_file_that_reparses_to_post_apply_map`, `test_hex_save_forces_hex_suffix_when_name_lacks_it`, `test_s19_save_still_forces_s19_suffix`, `test_hex_save_adversarial_filenames_contained_or_refused` (×4) | **PASS** | one `.hex` under `.s19tool/workarea/`, re-reads to map; parametric suffix (m-7); 4 adversarial names contained-or-refused w/ `MF_WRITE_CONTAINMENT` |
| HLR-002 | LLR-002.2 | TC-006 | `test_save_back_unsupported_source_refused_with_clear_issue` | **PASS** | `"mac"`→1 `CHG-HEX-SAVE-UNSUPPORTED` + 0 writes; `"hex"`→0 |
| HLR-002 | LLR-002.3 | TC-007 | `test_save_back_suggestion_is_format_aware` (I4 file) | **PASS** | HEX→`img-patched.hex`; S19 default stays `.s19` |
| HLR-003 | — | TC-008..010 | `test_verify_on_save.py` (8) + `test_changes_apply.py` verify nodes | **PASS** | verify-on-save engine + wiring |
| HLR-003 | LLR-003.1 | TC-008 | `test_identity_write_is_verified` (×2 hex/s19), `test_unsupported_file_type_raises` | **PASS** | parser selection per file_type; `"mac"`→`ValueError`; purity P-2 (0 textual) |
| HLR-003 | LLR-003.2 | TC-009 | `test_mutated_byte_is_mismatch_changed` (×2), `test_dropped_byte_is_mismatch_only_a` (×2) | **PASS** | M-2 form: MUTATION→`len(runs)==1 and runs[0].kind==KIND_CHANGED and runs[0].length==1`; M-4 DROP→one `KIND_ONLY_A` len1 |
| HLR-003 | LLR-003.3 | TC-010 | `test_verify_written_hex_image_is_verified`, `test_verify_on_dropped_byte_is_mismatch_file_kept`, `test_hex_save_stamps_verified_result_on_summary`, `test_refused_save_leaves_verify_result_none` | **PASS** | collect-don't-abort: injected DROP → file kept + `mismatch` + one `only_a` len1; verify rides `last_summary.verify_result` (C-10); 2-tuple unchanged |
| HLR-004 | — | TC-011a/b | `test_tui_patch_editor_v2.py` | **PASS** (test-realized demo) | quiet pass / loud mismatch |
| HLR-004 | LLR-004.1 | TC-011a | `test_verify_quiet_pass_on_faithful_hex_save` | **PASS** | one "Saved + verified" log line; 0 error notices; real round-trip `verified` |
| HLR-004 | LLR-004.2 | TC-011b | `test_verify_loud_mismatch_notice` | **PASS** | 1 error notice naming file + `changed 1 run / 1 byte`; file kept |
| HLR-005 | — | TC-012/013 | `test_tui_operations_view.py` | **PASS** | folded hygiene |
| HLR-005 | LLR-005.1 | TC-012 | `test_operations_button_row_has_screen_unique_id` | **PASS** | row id `operations_buttons`, `.modal-buttons` kept, `#load_buttons` query→0 |
| HLR-005 | LLR-005.2 | TC-013 | `test_execute_internal_keyerror_not_masked_as_unknown_operation` | **PASS** | M-3: resolver `KeyError`→1 "unknown operation"; `.execute`-internal `KeyError` propagates (raised=True), NOT masked |

**Per-requirement verdict: 5/5 HLR PASS, 14/14 LLR PASS. 0 fails, 0 skips.**

### 1.1 Executed per-TC commands + runtimes

All via `python -m pytest -q <node>` in the worktree (2026-06-14):

| Group | Node set | Result | Runtime |
|-------|----------|--------|---------|
| I1 emitter | `test_hex_emit.py` 8 functions (10 nodes w/ params) | 10 passed | 0.43s |
| I2 verify | `test_verify_on_save.py` 5 functions (8 nodes w/ params) | 8 passed | 0.40s |
| I3 apply | `test_changes_apply.py` 7 functions (10 nodes w/ params) | 10 passed | 0.46s |
| I3 service | `test_change_service.py` 2 functions | 2 passed | 0.39s |
| I4 TUI | `test_tui_patch_editor_v2.py` 3 + `test_tui_operations_view.py` 2 | 5 passed | 7.86s |

**Total targeted: 35 node-results, 35 passed, 0 failed, 0 skipped.** (35 vs 34-new delta: `test_save_back_unsupported_source...` is an extended pre-existing TC-006 test, not a brand-new node — see §3.)

### 1.2 LLR numeric-threshold verification (read from test source)

| LLR | Threshold | Met? | Source evidence |
|-----|-----------|------|------------------|
| LLR-001.1 | 0 textual in io.py; 0 import-graph offenders | YES | P-1 rg→0; `test_no_textual_in_static_import_graph` PASS |
| LLR-001.2 | `get_errors()` empty; ≤16 bytes/record | YES | test lines 92-100 |
| LLR-001.3 | `sum(record_type==0x04)>=1` for >0xFFFF; equality 100% | YES | lines 114-115 (`>=1`), 132-133 (`>=2`); `reread.memory==mem_map` |
| LLR-001.4 | one EOF; equality 100%; 0 errors | YES | lines 141, 157-158, 146-147, 170-171 |
| LLR-002.1 | exactly one `.hex`; 0 `CHG-HEX-SAVE-UNSUPPORTED` | YES | 443-450; suffix 469/487; adversarial 515-522 |
| LLR-002.2 | hex→0; mac→1 + 0 files | YES | 411-416 |
| LLR-002.3 | hex→`.hex`, s19→`.s19` | YES | 756-757 |
| LLR-003.1 | correct parser per file_type; 0 textual | YES | verify.py:112-116; `ValueError` test 139-140; P-2 rg→0 |
| LLR-003.2 | MUTATION→1 changed len1; DROP→1 only_a len1 (M-2/M-4) | YES | 107-111 + 128-132 (property reads `.kind`/`.length`/`.start`) |
| LLR-003.3 | DROP: file exists + mismatch + 1 only_a len1; 2-tuple unchanged | YES | 586-594; signature apply.py:581 |
| LLR-004.1 | one "saved+verified"; no notice | YES | 799-802 |
| LLR-004.2 | notice names file + non-zero; file kept | YES | 865-871 |
| LLR-005.1 | 0 cross-screen `load_buttons`; CSS preserved | YES | P-3 rg→0; query→0 + `.modal-buttons` 412-420 |
| LLR-005.2 | resolver miss→1 status; `.execute` KeyError propagates | YES | Phase A 337; Phase B raised==True 374-382 |

---

## 2. Inspections

rg exit=1 = 0 matches (a pass for absence checks).

### 2.1 Emitter purity (LLR-001.1, P-1)
`rg -n "import textual|from textual" s19_app/tui/changes/io.py` → **0 matches** (exit 1). Regime: whole-file purity, `tui/changes/` module (where the emitter lives, next to `emit_s19_from_mem_map`). **PASS.**

### 2.2 Verify purity (LLR-003.1, P-2)
`rg -n "import textual|from textual" s19_app/tui/changes/verify.py` → **0 matches** (exit 1). Regime: whole-file purity, `tui/changes/` module — P-2's in-regime control is now discharged (module exists, probed at actual location, retiring the draft `superseded-pending` flag). Cross-check: `test_no_textual_in_static_import_graph` (`test_checks_engine.py:400`) PASS with both new modules on the reachable graph. **PASS.**

### 2.3 hexfile.py PRISTINE — engine-frozen constraint that forced R2
- `git diff --stat main -- s19_app/hexfile.py` → **EMPTY** (no diff). Regime: `git diff vs main`, line-ending + `__pycache__` aware.
- `python -m pytest -q tests/test_engine_unchanged.py "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main" "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main"` → **3 passed 0.51s**.
- **PASS.** hexfile.py untouched (reader/oracle frozen); R2 (emitter→io.py) honored.

### 2.4 V-3 supersession-census completeness (incl. 4th guard family — batch-10 finding)
- **Family 1 (behavioral-placeholder):** `rg -ln "NotImplementedError|placeholder|calls <=" tests/` → hits in `test_operations.py` et al.; target operation placeholders, NOT save/emit path. Emitter/verify do not trip.
- **Family 2 (structural/placement/allowlist):** `rg -n 'glob("*.py")|_root_modules|package_root' tests/test_tui_directionb.py` → allowlists at 3191/3565, both `package_root.glob("*.py")`. io.py/verify.py live in `tui/changes/` (NOT package root) → absent.
- **Family 3 (AST composition):** `rg -ln "import ast|ast.parse" tests/` → present; no rule references emitter/verify symbols.
- **Family 4 (engine-frozen / no-diff-vs-main):** `rg -n "_ENGINE_PATHS|no_diff_vs_main|engine_modules_unchanged" tests/` → **10 hits** across `test_engine_unchanged.py` + `test_tui_directionb.py`.
  - **Frozen module set (union, read from source):** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` (color_policy in directionb tuple only). Citations: `test_engine_unchanged.py:120-127`, `test_tui_directionb.py:3738-3746`.
  - **Confirmation:** `rg -n "changes/io|changes/verify|changes.io|changes.verify" tests/test_engine_unchanged.py tests/test_tui_directionb.py` → **0 matches** (exit 1). **io.py and verify.py absent from the frozen set.**
- **PASS.** All 4 families enumerated; emitter (io.py) + verify (verify.py) trip NONE (both in `tui/changes/`, not frozen, not root). The 4th-family gap that broke original D-A=(a) is a post-mortem feeder (DEV-7).

### 2.5 M-1 back-compat (2-tuple return + unpack sites)
- `rg "def save_patched_image" -A12 s19_app/tui/changes/apply.py` → return `-> Tuple[Optional[Path], List[ValidationIssue]]` (apply.py:581). **2-tuple PRESERVED, 0 fields added.**
- Unpack sites `= save_patched_image(` → 2 production (`change_service.py:851`, `variant_execution_service.py:711`) + named pre-existing tests (`test_changes_apply.py:335,381,407`), all `(path/saved_path, issues)=...`. New I3 HEX tests (439-583) also 2-tuple. **All 5 named sites intact. PASS.**

### 2.6 Verify no-byte-leak (F-S-05)
`VerifyResult` fields = `status`, `runs: List[DiffRun]`, `stats: DiffStats`, `written_path: Optional[Path]` (verify.py:75-78). `DiffRun` = start/end/kind (addresses); `DiffStats` = run/byte COUNTS. TUI summary (app.py:1498-1504) emits only `run_counts`/`byte_counts` over `DIFF_KIND_DOMAIN` + the file name. **No raw mem_map byte in result or notice. PASS.**

### 2.7 N-3 (load_buttons rename + rail untouched)
- `rg -n 'id="load_buttons"' s19_app/tui/screens.py` → **0 matches** (exit 1). OperationsScreen uses `operations_buttons`. **PASS.**
- `git diff --stat main -- s19_app/tui/rail.py` → **EMPTY**. **PASS.**

### 2.8 M-3 (OperationsScreen `_execute_selected` scope)
`screens.py:620-650`: `operation = operation_service.operation_resolver(operation_id)` INSIDE `try/except KeyError` (630-635); `operation.execute(...)` OUTSIDE (636). Execute-internal KeyError not masked. **PASS.**

### 2.9 ELA oracle (LLR-001.3)
`test_hex_emit.py:103-118`: asserts `record_type==0x04` via `IntelHexFile(written).records` (114), fixture base `0x08040000` (≥0x10000, 106). Parser oracle, not string scan. **PASS.**

### 2.10 Byte-stability (MEASURE, not gate)
`test_hex_emit.py:174-191`: `test_byte_stability_measure` records `emit_parse_emit_byte_stable` via `record_property`, asserts only `isinstance(byte_stable, bool)`. No `emit(parse(file))==file` byte-identity assertion exists. Correctly a recorded measure. **PASS** (see DEV-9).

---

## 3. Signed-balance reconciliation

- `python -m pytest -q --collect-only` → last line **816 tests collected**.
- MEASURED baseline (Phase 1): **782**.
- Form: `collected_after == 782 − D + N_new`. **D = 0** (all-additive; M-1 back-compatible carrier left existing `test_save_back*` 2-tuple unpacks unmodified — no node lost/renamed-away).
- **N_new = 34**: **I1 +10** (`test_hex_emit.py` whole-file NEW), **I2 +8** (`test_verify_on_save.py` whole-file NEW), **I3 +11** (9 in `test_changes_apply.py` + 2 in `test_change_service.py`), **I4 +5** (3 in `test_tui_patch_editor_v2.py` + 2 in `test_tui_operations_view.py`).
- **Check: 782 − 0 + 34 = 816** ✓. No collection regression. **PASS.**

---

## 4. §5.3 batch acceptance criteria — verdicts

| # | Criterion | Verdict | Evidence |
|---|-----------|---------|----------|
| 1 | Collection == 782 − 0 + N_new (816), no regression | **PASS** | §3 |
| 2 | 100% LLRs covered by ≥1 passing TC; 0 blocker fails | **PASS** | §1: 14/14 LLR, 35 passing node-results |
| 3 | 0 `test`/`analysis` LLR missing Executed-verification + Numeric-threshold | **PASS** | self-check §6.3; all carry both |
| 4 | Two package-root allowlist guards (directionb 3191, 3565) GREEN | **PASS** | `test_tc028..._inc10` both passed (§2.4) |
| 5 | Headless-purity guard (`test_no_textual_in_static_import_graph`) GREEN | **PASS** | passed w/ new emitter + verify on reachable graph (§2.2) |
| — | Lean suite (`pytest -q -m "not slow"`) | **PASS** (orchestrator) | I4 close: **763 passed, 29 skipped, 21 deselected, 3 xfailed, 0 failed** (2026-06-14) |
| — | Full suite incl. slow (`pytest -q`) | **PASS** (orchestrator) | **784 passed, 29 skipped, 3 xfailed, 0 failed** in 658.73s (2026-06-14, exit 0). Reconciliation EXACT: 784+29+3 = 816 collected; 763 lean + 21 slow = 784 |

---

## 5. Deviations / gaps register

All DEV-class (doc-reconciliation / cosmetic), expected under V-5 or recorded for Phase 6. **None is a functional failure.**

| ID | Class | Description | Disposition |
|----|-------|-------------|-------------|
| DEV-1 | V-5 rename | Spec `test_operations.py -k "keyerror_scope..."` (TC-013) → `test_tui_operations_view.py::test_execute_internal_keyerror_not_masked_as_unknown_operation`. | Phase-6 reconcile; expected. |
| DEV-2 | V-5 rename | Spec `test_hex_emit.py -k "data_record/ela/roundtrip"` → descriptive function names; file path matched. | Phase-6; expected. |
| DEV-3 | V-5 rename | Spec `test_verify_on_save.py -k "reread/verified or mismatch"` → `test_identity_write_is_verified` / `test_mutated_byte_is_mismatch_changed` / `test_dropped_byte_is_mismatch_only_a` (parametrized hex/s19). | Phase-6; expected. |
| DEV-4 | V-5 rename + coverage-shift | Spec `test_change_service.py -k "hex_suffix or save_patched_hex"` → `test_hex_save_stamps_verified_result_on_summary` + `test_refused_save_leaves_verify_result_none`; LLR-002.3 suffix coverage realized at the TUI layer (`test_save_back_suggestion_is_format_aware`), not the service layer. Still covers LLR-002.3 threshold. | Phase-6; note coverage-location shift. |
| DEV-5 | V-5 doc note | In-file TC labels lag the spec table: `test_tui_operations_view.py` docstring says TC-010..TC-012; `test_changes_apply.py` header reads TC-009..TC-013 (older engine numbering). Spec §5.2 ids (TC-005..013) map per §1. | Phase-6 doc-reconcile; cosmetic. |
| DEV-6 | V-5 doc note | `test_hex_emit.py` module docstring says "D-A=(a) R2-relocated" — inconsistent; D-A resolved to **(c)** per H-5. Relocation outcome (io.py) correct; only the option-letter label is wrong. | Phase-6; cosmetic typo, no behavioral impact. |
| DEV-7 | Post-mortem feeder | The 4th guard family (engine-frozen / no-diff-vs-main) was MISSED by the Phase-1/2 census, breaking original D-A=(a) `hexfile.py` placement at I1 (forcing R2). The V-3 census-completeness greps must permanently include `rg "_ENGINE_PATHS\|no_diff_vs_main\|engine_modules_unchanged" tests/`. | Captured in §6.3 R-10-ENGINE-FROZEN + H-5; carry to Phase 5 post-mortem as a process-rule extension. |
| DEV-8 | Tidy item | `emit_intel_hex_from_mem_map` is NOT re-exported from `s19_app/tui/changes/__init__.py`, whereas its precedent `emit_s19_from_mem_map` IS (`__init__.py:45,109`). Tests import directly from `...changes.io`, so functionally inert. | Phase-6 tidy (add re-export for symmetry); low priority, no functional gap. |
| DEV-9 | Measure (informative) | Byte-stability is a recorded MEASURE (`record_property`), not a gate — by design (canonicalization expected). No `emit(parse(file))==file` assertion. | None required; recorded per spec §5. |

---

## 6. Final verdict

**PASS-WITH-NOTES** — now INCLUDING the orchestrator-owned rows (lean 763/0, full 784/0, reconciliation 816 exact). All §5.3 criteria PASS.

**Orchestrator recommendation (2026-06-14, per-gate cadence — AWAITING operator gate):** PASS-WITH-NOTES, 0 code/behavior defects; recommend approve. The 9 DEV notes are doc-reconciliation (DEV-1..6 V-5 provisional→implemented renames + the DEV-6 D-A option-letter typo), the 4th-guard-family census-rule extension (DEV-7 → Phase-5 post-mortem + a template widening), and two tidies (DEV-8 `__init__` re-export, DEV-9 byte-stability measure) → all routed to Phase 6 docs / Phase 5. On approval → Phase 5.

- 5/5 HLR, 14/14 LLR PASS; 35/35 targeted node-results pass; 0 fails, 0 skips.
- All 10 inspections PASS (purity ×2, hexfile pristine + engine-frozen guards, 4-family census, M-1, no-byte-leak, N-3, M-3, ELA oracle, byte-stability measure).
- Signed-balance reconciled: 816 = 782 − 0 + 34, no collection regression.
- §5.3 criteria 1-5 PASS; rows 6-7 (lean/full suite) ORCHESTRATOR-OWNED.
- "WITH-NOTES" = 9 DEV-class deviations (V-5 renames DEV-1..6, 4th-guard-family post-mortem feeder DEV-7, `__init__` re-export tidy DEV-8, byte-stability measure DEV-9). **None is a functional failure or blocker.**
