# Validation Report — s19_app — Batch 2026-06-16-batch-12 (CRC_F2)

> Phase 4 (Validation). Authored by qa-reviewer. Honors the §6.4 withdrawals/re-scopes (LLR-002.5 WITHDRAWN; LLR-003.5 RE-SCOPED; I4/report_service withdrawn; TC-117 withdrawn). Every node id below was grep/collect-verified against the real tree on 2026-06-17, not signed off from intent.

---

## BLUF — Verdict: **PASS-WITH-NOTES**

- **All 17 in-scope requirements PASS** (5 HLR + 12 in-scope LLR). One LLR (LLR-002.5) is **WITHDRAWN** (J-3), correctly recorded as not-a-gap.
- **0 FAIL, 0 blockers.** The gating KAT anchor (TC-101 `crc32(b"123456789") == 0xCBF43926`) is present and passing; the confirmation gate, reader-as-oracle (with injected map + non-tautological corrupted negative), and containment seam are all exercised.
- **TC reconciliation: clean.** Every in-scope spec TC maps to a real, passing node on disk. TC-117 is correctly absent (withdrawn). No orphan CRC test is untraceable to a TC — the extra implemented nodes are named, in-scope hardening (over-cap, missing-field, parse-text surface, stale-worker race, write-outside-workarea, schema/passthrough regression).
- **Surface-reachability (A-5 / SCOPE-1): clean.** Every US-011/US-012 input dimension is exercised through the shipped TUI handler (TC-115 check path; TC-124/TC-125 write path, pilot-driven `ConfirmWriteScreen`), not only via direct service kwargs.
- **Frozen-set: CLEAR.** `test_engine_unchanged.py` green; no frozen path edited.
- **Notes (non-blocking):** (1) RK-3 non-default-vector residual remains a flagged "assumed" data dependency — partially closed by `test_bitwise_path_reproduces_published_variant_kats` (published variant KATs), still no operator *device* vector; (2) REQUIREMENTS.md does not yet reference REQ-crc.md (Phase-6 deferral — the co-located doc itself exists and is the C-7 obligation); (3) A2L not in scope, CLI deferred (TUI-only), no report_service surface (J-3).

**CRC test-file run (2026-06-17):**
`python -m pytest -q tests/test_crc_engine.py tests/test_crc_config.py tests/test_crc_operation.py tests/test_tui_crc_surface.py tests/test_operations.py tests/test_tui_operations_view.py`
→ **53 passed in 43.52s.** Full suite (incl. `slow`), orchestrator-run: **847 passed / 0 failed / 29 skipped / 3 xfailed** (exit 0); lean **826 passed**; signed-balance 879 = 839 + 40 (D=0/A=40). See §5.

---

## 1. Per-requirement pass/fail matrix

Method legend: U=unit, I=integration, E=e2e pilot, X=inspection.

### HLRs

| Req | Method | Result | Evidence (real node / inspection) |
|---|---|---|---|
| **HLR-001** CRC32 compute engine (headless) | U | **PASS** | `test_crc_engine.py::{test_known_answer_vector, test_segment_chaining_does_not_reset_state, test_gap_splits_segments_no_inserted_bytes, test_ascending_address_ordering, test_region_filter_excludes_out_of_range, test_entry_point_does_not_mutate_mem_map}` all pass. KAT==`0xCBF43926` (`test_crc_engine.py:36`). |
| **HLR-002** Region check + compare + report (non-mutating) | I+demo | **PASS** | `test_crc_operation.py::{test_check_reports_match_nonmutating, test_check_reports_mismatch, test_execute_with_config_populates_crc_regions}`; non-mutation asserted (`test_crc_operation.py:186` `output.mem_map == mem`). Demo = manual (left blank). |
| **HLR-003** Inject + emit + verify (operator-confirmed) | I+demo | **PASS** | `test_crc_operation.py::{test_inject_writes_le_at_output_address, test_inject_into_gap_extends_ranges, test_modified_s19_reread_matches_intent, test_write_only_when_invoked, test_write_result_records_emitted_path_and_verdict}`; confirm gate `test_tui_crc_surface.py::test_no_write_without_confirmation`. Demo = manual (blank). |
| **HLR-004** Config sourcing (JSON) + TUI text surface | U+demo | **PASS** | `test_crc_config.py` (10 nodes, all pass); surface `test_tui_crc_surface.py::test_crc_config_error_surfaces_error_and_no_match`. Demo = manual (blank). |
| **HLR-005** Neutral input contract + `OperationResult` widening | U+X | **PASS** | `test_operations.py::{test_operation_input_exposes_mem_map_ranges_metadata, test_operation_result_widened_field_count_and_status_domain}` + full `test_operations.py` green (10 nodes, 0 regressions). |

### LLRs

| LLR | Method | Result | Evidence |
|---|---|---|---|
| **LLR-005.1** Neutral `OperationInput` + both call-sites migrated | U | **PASS** | `test_operations.py::test_operation_input_exposes_mem_map_ranges_metadata`; `test_run_operation_service`, `test_operation_interface` green (service path migrated). |
| **LLR-005.2** `OperationResult` widened (contract-touch) | U+X | **PASS** | `test_operations.py::test_operation_result_widened_field_count_and_status_domain` (7+1 field count, `STATUS_DOMAIN` unchanged, `to_dict` deterministic). |
| **LLR-005.3** Co-located `REQ-crc.md` | X | **PASS** | `ls s19_app/tui/operations/requirements/REQ-crc.md` → exists. Note: `REQUIREMENTS.md` reference line not yet present (Phase-6 task — see Notes). |
| **LLR-001.1** Parameterized CRC32 core | U | **PASS** | `test_crc_engine.py::{test_known_answer_vector, test_config_params_change_result, test_bitwise_path_reproduces_published_variant_kats}`. |
| **LLR-001.2** Region byte assembly (sort/filter/segment/chain) | U | **PASS** | `test_crc_engine.py::{test_segment_chaining_does_not_reset_state, test_gap_splits_segments_no_inserted_bytes, test_ascending_address_ordering, test_region_filter_excludes_out_of_range}`. |
| **LLR-001.3** Per-region payload, no mutation | U | **PASS** | `test_crc_operation.py::test_check_multi_region_order` (order) + `test_crc_engine.py::test_entry_point_does_not_mutate_mem_map` (0 mutation). |
| **LLR-004.1** External JSON config reader (resolve+parse+collect) | U | **PASS** | `test_crc_config.py::{test_params_loaded_from_synthetic_json, test_unresolvable_path_collects_one_error, test_malformed_json_collects_one_error, test_over_size_cap_collects_one_error_without_reading, test_missing_field_collects_one_error}` — each failure → exactly 1 error, `None` config, no raise. |
| **LLR-004.2** TUI editable text config surface | E+I | **PASS** | `test_crc_config.py::{test_parse_crc_config_valid_text_populates_config, test_parse_crc_config_dummy_prefill_is_valid, test_parse_crc_config_malformed_text_collects_one_error, test_parse_crc_config_non_object_top_level_collects_one_error, test_parse_crc_config_missing_field_collects_one_error}` + `test_tui_crc_surface.py::test_crc_config_error_surfaces_error_and_no_match`. Demo = manual (blank). |
| **LLR-002.1** Read stored 4-byte LE | U | **PASS** | `test_crc_operation.py::{test_check_reports_match_nonmutating, test_read_stored_missing_returns_none}` (missing high byte → no stored value, no exception). |
| **LLR-002.2** Compare + per-region payload (non-mutating) | I | **PASS** | `test_crc_operation.py::{test_check_reports_match_nonmutating, test_check_reports_mismatch, test_execute_with_config_populates_crc_regions}`; `output.mem_map == mem` (`:186`). |
| **LLR-002.3** Check execution on worker-thread (R-6) | X+I | **PASS** | `test_tui_crc_surface.py::test_crc_execute_path_uses_thread_worker` (CRC execute path uses `@work(thread=True)`); stale-worker race covered `::test_stale_crc_worker_result_does_not_overwrite_error`. |
| **LLR-002.4** Render per-region results in op-result view | E | **PASS** | `test_tui_crc_surface.py::test_crc_check_reaches_result_surface_via_handler` (through-handler reachability, A-5). |
| **LLR-002.5** ~~Persistent project-report render~~ | — | **WITHDRAWN (J-3)** | Not a gap. `report_service` is `VariantExecutionResult`-scoped; CRC is per-file. Check has no separate persistent artifact; surface = op-result view (LLR-002.4). TC-117 removed. |
| **LLR-003.1** Inject 4-byte LE + write-into-gap range extension | U | **PASS** | `test_crc_operation.py::{test_inject_writes_le_at_output_address, test_inject_into_gap_extends_ranges}`; original snapshot byte-for-byte unchanged (`:259-260`, `:294`); ranges kept sorted/non-overlapping. |
| **LLR-003.2** Emit via `emit_s19_from_mem_map` into contained work area | I | **PASS** | `test_crc_operation.py::{test_modified_s19_reread_matches_intent, test_write_outside_workarea_collects_finding_and_writes_no_file}`; containment via workarea seam, escaping target → 1 finding + 0 files. |
| **LLR-003.3** Verify written image (reader-as-oracle) | I | **PASS** | `test_crc_operation.py::test_modified_s19_reread_matches_intent` — clean → `STATUS_VERIFIED` + empty runs; deliberately corrupted write → `mismatch` + non-empty runs (non-tautological, `:323-324`). `intended_mem_map` = INJECTED working copy (F-Q-05, `:327`). |
| **LLR-003.4** Two-stage operator confirmation gates the write (R-6) | I+demo | **PASS** | `test_tui_crc_surface.py::test_no_write_without_confirmation` — decline `ConfirmWriteScreen` → 0 files; confirm → 1 emitted file. Pilot-driven via `#confirm_write_ok`/`#confirm_write_cancel` buttons (`:357-359`). Demo = manual (blank). |
| **LLR-003.5** Persistent record via operation output (RE-SCOPED) | I | **PASS** | `test_crc_operation.py::test_write_result_records_emitted_path_and_verdict` — confirmed write → emitted path + `written=True` + verify verdict; no-confirm → no path, `written=False`. NO report_service binding (correct per J-3). |

**Score: 5/5 HLR PASS · 12/12 in-scope LLR PASS · 1 LLR WITHDRAWN (not counted as gap) · 0 FAIL · 0 N/A.**

---

## 2. TC reconciliation (V-5) — spec TC → implemented node

Each implemented node confirmed present via `pytest --collect-only` on 2026-06-17.

| Spec TC | Spec intent | Implemented node (on disk) | Status |
|---|---|---|---|
| **TC-101** (gating) | KAT `crc32(b"123456789")==0xCBF43926` | `test_crc_engine.py::test_known_answer_vector` | PASS |
| TC-102 | Segment chaining, no state reset | `test_crc_engine.py::test_segment_chaining_does_not_reset_state` | PASS |
| TC-103 | Gap-split, no inserted bytes | `test_crc_engine.py::test_gap_splits_segments_no_inserted_bytes` | PASS |
| TC-104 | Ascending-address ordering | `test_crc_engine.py::test_ascending_address_ordering` | PASS |
| TC-105 | Region filtering | `test_crc_engine.py::test_region_filter_excludes_out_of_range` | PASS |
| TC-106 | Params WIRED (non-default changes digest) | `test_crc_engine.py::test_config_params_change_result` | PASS |
| **TC-106b** | Bitwise path vs published variant KATs (RK-3 partial close) | `test_crc_engine.py::test_bitwise_path_reproduces_published_variant_kats` | PASS |
| TC-107 | 4-byte LE codec round-trip | `test_crc_engine.py::test_le_codec_roundtrip` | PASS |
| **TC-108** | Neutral `OperationInput` exposes mem_map+ranges+metadata | `test_operations.py::test_operation_input_exposes_mem_map_ranges_metadata` | PASS |
| **TC-109** | `OperationResult` widened 7+1; STATUS_DOMAIN unchanged | `test_operations.py::test_operation_result_widened_field_count_and_status_domain` | PASS |
| TC-111 | Compare MATCH, non-mutating | `test_crc_operation.py::test_check_reports_match_nonmutating` | PASS |
| TC-112 | Compare MISMATCH | `test_crc_operation.py::test_check_reports_mismatch` | PASS |
| TC-113 | Params from synthetic JSON | `test_crc_config.py::test_params_loaded_from_synthetic_json` | PASS |
| TC-114 | Config-never-in-repo (negative) | `test_crc_config.py::test_no_real_config_required` | PASS |
| **TC-115** | Surface reachability (check via handler, A-5) | `test_tui_crc_surface.py::test_crc_check_reaches_result_surface_via_handler` | PASS |
| **TC-116** | Check execute path `@work(thread=True)` | `test_tui_crc_surface.py::test_crc_execute_path_uses_thread_worker` | PASS |
| ~~TC-117~~ | ~~report_service check-section~~ | **— (WITHDRAWN J-3)** | correctly absent |
| **TC-121** | Inject 4-byte LE at output addr | `test_crc_operation.py::test_inject_writes_le_at_output_address` | PASS |
| TC-122 | Write-into-gap extends mem_map+ranges | `test_crc_operation.py::test_inject_into_gap_extends_ranges` | PASS |
| **TC-123** | Reader-as-oracle (VERIFIED + empty diff; corrupted→mismatch) | `test_crc_operation.py::test_modified_s19_reread_matches_intent` | PASS |
| TC-124 | No write without confirmation | headless: `test_crc_operation.py::test_write_only_when_invoked` + confirm-gate: `test_tui_crc_surface.py::test_no_write_without_confirmation` | PASS |
| **TC-125** | Surface reachability (inject via handler, pilot-driven) | `test_tui_crc_surface.py::test_crc_inject_reaches_surface_via_handler` | PASS |
| **TC-126** | Write `OperationResult` records emitted path + verdict | `test_crc_operation.py::test_write_result_records_emitted_path_and_verdict` | PASS |
| (stale-worker race) | Stale worker result must not overwrite error | `test_tui_crc_surface.py::test_stale_crc_worker_result_does_not_overwrite_error` | PASS |
| TC-131 | REQ-crc.md co-located | inspection: `REQ-crc.md` exists | PASS (see note on REQUIREMENTS.md ref) |
| TC-132 | Frozen-set clearance | `test_engine_unchanged.py` (1 passed) | PASS |

**Spec TCs with no implemented node:** NONE in scope. TC-117 is intentionally withdrawn (J-3) — not a gap.

**Implemented CRC nodes not traced to a spec TC (all named, in-scope hardening — no orphans):**
- `test_crc_config.py::{test_unresolvable_path_collects_one_error, test_malformed_json_collects_one_error, test_over_size_cap_collects_one_error_without_reading, test_missing_field_collects_one_error}` → LLR-004.1 collect-don't-abort failure modes (named in LLR-004.1 executed-verification).
- `test_crc_config.py::{test_parse_crc_config_valid_text_populates_config, test_parse_crc_config_dummy_prefill_is_valid, test_parse_crc_config_malformed_text_collects_one_error, test_parse_crc_config_non_object_top_level_collects_one_error, test_parse_crc_config_missing_field_collects_one_error}` → LLR-004.2 TUI text-parse surface.
- `test_crc_operation.py::{test_read_stored_missing_returns_none, test_check_multi_region_order, test_execute_no_config_returns_ok_no_regions, test_execute_with_config_populates_crc_regions, test_write_outside_workarea_collects_finding_and_writes_no_file}` → LLR-002.1/.3, LLR-001.3, LLR-002.2, LLR-003.2 containment.
- `test_operations.py::{test_operation_result_schema, test_identity_passthrough_s19, test_identity_passthrough_hex, test_placeholders_registered, test_registry_deterministic_order, test_unknown_operation_raises, test_run_operation_service, test_operation_interface}` → HLR-005 regression net (placeholders survive the widening).

**Result: all in-scope spec TCs have a real, passing node; 0 orphans (every extra node maps to a named LLR obligation).**

---

## 3. Surface-reachability matrix (A-5 / SCOPE-1 control)

For each US-011/US-012 input dimension: confirm ≥1 TC drives it **through the shipped TUI handler**, not only via direct service kwargs.

| Input dimension | Direct-service TC | Through-handler TC | Through-handler proof | Status |
|---|---|---|---|---|
| Configured CRC range(s) | TC-105 | TC-115 | `test_crc_check_reaches_result_surface_via_handler` runs `crc` through `OperationsScreen`→handler | covered |
| Output address(es) | TC-111/TC-121 | TC-115, TC-125 | check + inject via handler | covered |
| Poly/init/reverse/xorout params | TC-106/TC-113 | TC-115 | config threaded through surface (error path `test_crc_config_error_surfaces_error_and_no_match`) | covered — params-WIRED; non-default *device* correctness RK-3-deferred |
| Stored 4-byte LE value (check) | TC-111/TC-112 | TC-115 | check verdict reaches result surface | covered |
| Inject + modified-S19 emit | TC-121/TC-123 | TC-125 | `test_crc_inject_reaches_surface_via_handler` — confirmed write's emitted path reaches surface | covered |
| Operator confirmation (two-stage) | TC-124 (headless `test_write_only_when_invoked`) | TC-124 confirm-gate + TC-125 | `test_no_write_without_confirmation` drives `ConfirmWriteScreen` via pilot button press (`#confirm_write_ok`/`#confirm_write_cancel`), NOT a `confirm=True` kwarg | covered (pilot-driven, F-Q-06 satisfied) |
| Result in op-result view (F-A-01 surface a) | — | TC-115 / LLR-002.4 | per-region rows rendered via handler | covered |
| Persistent record of the WRITE (re-scoped J-3) = emitted S19 + `OperationResult` | TC-126 | TC-125 | write result record + inject-reaches-surface | covered |

**No dimension is covered headlessly only.** The two highest-risk write dimensions (inject/emit, confirmation) are both pilot-driven through the real Textual screen — the batch-11 SCOPE-1 failure mode (writer tested via kwargs while handler defaults empty) does not recur here. **Surface-reachability result: CLEAR.**

---

## 4. Inspections

| # | Inspection | Result | Evidence |
|---|---|---|---|
| (a) | **KAT anchor TC-101 GATING** | **PASS** | `crc32_stream(b"123456789") == 0xCBF43926` asserted at `tests/test_crc_engine.py:36`; node `test_known_answer_vector` passes. Without it the engine would be only self-consistent — it is present and green. |
| (b) | Reader-as-oracle verify uses the **injected** map | **PASS** | `intended_mem_map` = INJECTED working copy that was emitted (F-Q-05), documented `test_crc_operation.py:327`; clean→`STATUS_VERIFIED`+empty runs, corrupted→`mismatch`+≥1 run (`:323-324`) — non-tautological. |
| (c) | Config collect-don't-abort never raises | **PASS** | `read_crc_config` returns `(config, errors)`; every failure mode asserts `config is None` + `len(errors) == 1` with no `pytest.raises` (`test_crc_config.py:126-186`). 5 distinct failure modes covered. |
| (d) | Write containment bound to workarea resolved-path seam; no operator-arbitrary path | **PASS** | `test_write_outside_workarea_collects_finding_and_writes_no_file` — escaping target → 1 finding + 0 files; in-area write validated against `ensure_workarea`/`WORKAREA_SUBDIR`. Emit `workarea_base` is the contained root, not an operator-typed output path. |
| (e) | NO write without confirmation (TC-124) | **PASS** | `test_no_write_without_confirmation` (declining `ConfirmWriteScreen` → 0 files) + headless `test_write_only_when_invoked`. |
| (f) | F-L1 distinction (verified / mismatch / write-failed; no stale MISMATCH on verified write) | **PASS** | TC-123 distinguishes `verified` vs `mismatch`; TC-126 records the verdict per region; stale-worker race guarded by `test_stale_crc_worker_result_does_not_overwrite_error` (a late worker result does not clobber a surfaced error/verdict). |
| (g) | Original `mem_map` immutable on inject | **PASS** | inject works on WORKING copy; original byte-for-byte unchanged (`test_crc_operation.py:259-260` in-range, `:294` gap case). |
| (h) | Change-first census revalidation — NO frozen path edited | **PASS** | `python -m pytest -q tests/test_engine_unchanged.py` → **1 passed**. No diff-vs-main on any frozen engine module. |
| (i) | C-7 REQ-crc.md co-located | **PASS (with note)** | `s19_app/tui/operations/requirements/REQ-crc.md` exists. **Note:** the `REQUIREMENTS.md` back-reference line is not yet present — a Phase-6 docs task, not an I-increment obligation; flagged in Notes, non-blocking. |
| (j) | Operations result `output` contract (check = input snapshot) | **PASS** | `test_crc_operation.py:186` asserts `result.output.mem_map == mem` (check path → unchanged input snapshot). Inject path → `LoadedFile` over injected map (TC-125 surface). |

**All 10 inspections PASS** (one with a noted Phase-6 docs deferral, non-blocking).

---

## 5. Surface boundary / gaps / notes (honest)

- **A2L** — not in scope this batch (CRC inputs are S19 only). Correct.
- **CLI (`ops` subcommand)** — deferred at batch-08; this batch is **TUI-only**. No CLI surface validated, by design. Correct.
- **Non-S19 input formats (HEX/MAC as CRC inputs)** — out of scope.
- **RK-3 non-default-vector residual** — TC-106 proves params are WIRED; `test_bitwise_path_reproduces_published_variant_kats` (TC-106b) now anchors the bitwise path against *published* CRC-32 variant KATs, which is stronger than the Phase-1 self-consistency-only state. The residual that remains genuinely "assumed" is a real operator *device* convention reference vector — still not in the tree. Non-blocking, correctly flagged; do not trust a non-zlib device verdict without an operator-sourced vector.
- **J-3 re-scope (no report_service surface)** — validated as withdrawn, not as a gap. LLR-002.5 withdrawn; LLR-003.5 re-scoped to the operation's own output; TC-117 absent; `report_service.py` untouched. Surface = op-result view + emitted modified S19 + `OperationResult`. Consistent across the matrix.
- **REQUIREMENTS.md → REQ-crc.md reference** — the co-located doc exists (the C-7 obligation), but the repo-wide `REQUIREMENTS.md` does not yet carry the reference line / `R-*` status update. This is the Phase-6 docs step in the plan, not an implementation gap. Noted.
- **Full suite (incl. `slow`)** — orchestrator ran `python -m pytest -q` once (2026-06-17): **847 passed, 29 skipped, 3 xfailed, 0 failed (exit 0)** in 822.53s. Reconciliation: collection 879 = 847 + 29 skipped + 3 xfailed ✓. Signed-balance vs batch-11 close: **879 = 839 + 40** (D=0, A=40 — I1a+2, I1b+9, I2+10, I3a+2, I3b+9, I5a+6, I5b+2 = 40, EXACT). Lean (`-m "not slow"`) **826 passed**; the 21 slow tests bring full to 847. `test_engine_unchanged.py` 1 passed (no frozen path edited). The CRC-file subset is 53 passed.

---

## 6. Phase-4 evidence checklist

| # | Item | PASS/FAIL | Evidence |
|---|---|---|---|
| 1 | Per-requirement matrix complete (every HLR + in-scope LLR) | **PASS** | §1 — 5 HLR + 12 LLR + 1 withdrawn, all with node ids. |
| 2 | Each result has concrete PASS/FAIL/N-A + real evidence (no intent sign-off) | **PASS** | Every row cites a collect-verified node or an inspection result. |
| 3 | LLR-002.5 recorded WITHDRAWN, not FAIL | **PASS** | §1 + §2 — J-3 withdrawal honored. |
| 4 | TC reconciliation: every in-scope spec TC → real node; orphans flagged | **PASS** | §2 — all mapped; TC-117 correctly absent; extra nodes traced to named LLRs (0 orphans). |
| 5 | Surface-reachability: every US dimension through-handler | **PASS** | §3 — all 8 dimensions covered through the shipped handler; confirm pilot-driven. |
| 6 | KAT anchor (TC-101) gating + present | **PASS** | §4(a) — `test_crc_engine.py:36`. |
| 7 | Reader-as-oracle uses injected map + non-tautological negative | **PASS** | §4(b) — corrupted-write mismatch case. |
| 8 | Config collect-don't-abort never raises | **PASS** | §4(c) — 5 failure modes, `(config, errors)` tuple, no raise. |
| 9 | Write containment bound to workarea seam; no arbitrary path | **PASS** | §4(d) — write-outside-workarea negative. |
| 10 | No write without confirmation | **PASS** | §4(e) — pilot decline → 0 files. |
| 11 | Original mem_map immutable on inject | **PASS** | §4(g). |
| 12 | Frozen-set clearance re-run | **PASS** | §4(h) — `test_engine_unchanged.py` 1 passed. |
| 13 | CRC test-file run count pasted | **PASS** | 53 passed (header + §5). |
| 14 | No real PII / secrets / real config in tree | **PASS** | TC-114 `test_no_real_config_required` green; only dummy `examples/crc_config.example.json`. |
| 15 | Gaps/notes recorded honestly | **PASS** | §5 — RK-3 residual, REQUIREMENTS.md ref deferral, A2L/CLI/J-3 boundaries. |

---

*Generated 2026-06-17 by qa-reviewer (dev-flow Phase 4). UTF-8, no BOM.*
