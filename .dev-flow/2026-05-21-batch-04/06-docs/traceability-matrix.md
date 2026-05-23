# Traceability Matrix — s19_app — Batch 2026-05-21-batch-04

> Full chain: **User Story → HLR → LLR → Test Case → Increment → Validation verdict**.
> Every row is complete at batch close (Phase 6). Incomplete rows = coverage gaps and are listed in the gaps section.

This matrix is the consolidated traceability artefact for batch `2026-05-21-batch-04` — the **memory-value editing + unified change-set + selective-export** feature of the `s19tui` Textual TUI. Source artefacts:

- [`.dev-flow/2026-05-21-batch-04/01-requirements.md`](../01-requirements.md) §2.6 (US), §3 (HLR), §4 (LLR), §5.2/§5.3 (TC IDs + methods), §5.7 (TC catalogue)
- [`.dev-flow/2026-05-21-batch-04/02-review.md`](../02-review.md) §Phase-2 closure (22 findings closed, CV-01/CV-02 folded into Phase 3 increment 1)
- [`.dev-flow/2026-05-21-batch-04/03-increments/increment-001.md`](../03-increments/increment-001.md) … [`increment-009.md`](../03-increments/increment-009.md) + [`increment-plan.md`](../03-increments/increment-plan.md)
- [`.dev-flow/2026-05-21-batch-04/04-validation.md`](../04-validation.md) §5 (per-TC verdicts), §6 (per-requirement verdicts), §7 (§5.9 acceptance criteria), §8 (gaps)
- [`.dev-flow/2026-05-21-batch-04/05-postmortem.md`](../05-postmortem.md)

Like batch-03, this batch **deliberately adds a data layer** beside the batch-03 `cdfx/` package: a memory-change model, a unified change-set container, a JSON file handler, and a selective-export coordinator. The expansion was approved and expected ([`01-requirements.md`](../01-requirements.md) §1.1, §2.1). The engine remains frozen — the Phase-4 `git diff main` over `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` is empty (zero bytes changed); the batch-03 CDFX writer/resolver (`writer.py`, `resolve.py`) and the batch-03 `changelist.py` / `reader.py` are byte-unchanged. The batch-04 feature is purely additive new files.

---

## 1. Master table

One row per US → HLR → LLR → TC tuple. `Increment` cites the Phase-3 increment that built the feature and shipped the asserting test (the 9-increment sequence — model → validation → display → container → write → read → export → UI → round-trip/integration; see [`increment-plan.md`](../03-increments/increment-plan.md)). `Verdict` is the Phase-4 per-TC verdict from [`04-validation.md`](../04-validation.md) §5: `pass` = an asserting test is green in the Phase-4 evidence run / the inspection checklist is fully satisfied. All 5 US, 9 HLR, 37 LLR and 37 TC are traced — see §3 for the no-gap confirmation.

| US | HLR | LLR | TC | Method | Increment | Verdict | Evidence (Phase 4) |
|----|-----|-----|-----|--------|-----------|---------|--------------------|
| US-001 | HLR-001 | LLR-001.1 | TC-001, TC-004 | U | 1 | pass | `test_memory_changelist.py` — `MemoryChange` reports `address` / `new_bytes` / status; `new_bytes` preserves order/length, stored as an immutable tuple; the addressed range is the half-open `(address, address+len)` span. |
| US-001 | HLR-001 | LLR-001.2 | TC-002, TC-004 | U | 1 | pass | `test_memory_changelist.py` — add-then-remove empties the list; edit touches only the target entry; edit/remove of a missing address raises `KeyError`. |
| US-001 | HLR-001 | LLR-001.3 | TC-002 | U | 1 | pass | `test_memory_changelist.py` — `address` is the entry identity; re-adding the same `address` updates in place (one entry, latest bytes), preserves insertion position. |
| US-001 | HLR-001 | LLR-001.4 | TC-003 | U | 1 | pass | `test_memory_changelist.py` — two serializations of the same list produce identical entry order; `entries` is a defensive copy, not the backing store. |
| US-002 | HLR-002 | LLR-002.1 | TC-005 | U | 2 | pass | `test_memory_validate.py` — against a `make_ranged_s19` `LoadedFile`: whole-run-inside → `inside`; run crossing a range end → `partial`; run in the inter-range gap → `outside`; the gap-spanning run receives the single status `partial`; validator reads `LoadedFile.ranges`, no firmware re-parse. |
| US-002 | HLR-002 | LLR-002.2 | TC-006 | U | 2 | pass | `test_memory_validate.py` — `outside`, `partial` and the gap-spanning entry each collect exactly one warning `ValidationIssue`; an `inside` entry collects none; the validator never raises; the issue message omits the raw `new_bytes` content (C-9 / S-006). |
| US-002 | HLR-002 | LLR-002.3 | TC-007 | U | 2 | pass | `test_memory_validate.py` — with no image (and with an empty-ranges image) every entry is marked `unvalidated-no-image`; an empty list returns no issues; no exception. |
| US-002 | HLR-002 | LLR-002.4 | TC-008 (overlap arm) | U | 2 | pass | `test_memory_validate.py` — the factory overlap pair (`0x100 len 8` + `0x104 len 8`, distinct keys) each collect exactly one overlap warning; non-overlapping entries collect none; message omits raw bytes; no exception. |
| US-002 | HLR-002 | LLR-002.5 | TC-008 (`ValueError` arms) | U | 1 | pass | `test_memory_changelist.py` — constructing a `MemoryChange` with a byte `256`, a negative byte, or an empty `new_bytes` run each raises `ValueError`; the malformed run is also rejected via `MemoryChangeList.add` / `.edit`. |
| US-003 | HLR-003 | LLR-003.1 | TC-009 | U | 3 | pass | `test_memory_display.py` — `[0x01,0xAB,0xFF]` renders `01 AB FF` (uppercase, two-digit, space-separated); small bytes pad to two digits; a single byte renders with no separator. |
| US-003 | HLR-003 | LLR-003.2 | TC-010 | U | 3 | pass | `test_memory_display.py` — `[0x41,0x42]` renders ASCII `AB` and decimal `65 66`; a non-printable byte renders as the exact `.` placeholder (0x2E) — `test_tc010_non_printable_byte_renders_as_the_exact_dot_placeholder` asserts the literal character (CV-01 closure); 0x20 and 0x7E boundaries render as characters; all three forms returned in a `MemoryValueRendering`. |
| US-003 | HLR-003 | LLR-003.3 | TC-011 | U | 3 | pass | `test_memory_display.py` — stored `new_bytes` is byte-identical before and after every rendering call; repeated rendering is stable and non-mutating; a caller-supplied list is not mutated. |
| US-004 | HLR-004 | LLR-004.1 | TC-012, TC-026 | U | 4 | pass | `test_unified_changeset.py` — `UnifiedChangeSet` exposes its parameter `ChangeList` and `MemoryChangeList` as distinct, independently-accessible attributes; the parameter half carries no `ResolutionResult` (resolution-free container, A-7). |
| US-004 | HLR-004 | LLR-004.2 | TC-027, TC-026 | INSP | 4, 9 | pass | [`04-validation.md`](../04-validation.md) §4 — §5.6 checklist passes; `test_unified_changeset.py::test_tc026_unified_change_set_is_not_a_subclass` asserts `UnifiedChangeSet` is not a `ChangeList`/`MemoryChangeList` subclass; the halves are held by composition; `changelist.py` byte-unchanged. |
| US-004 | HLR-004 | LLR-004.3 | TC-013 | U | 4 | pass | `test_unified_changeset.py` — mutating the memory half leaves the parameter half unchanged and vice versa. |
| US-004 | HLR-004 | LLR-004.4 | TC-013 | U | 4 | pass | `test_unified_changeset.py` — an empty container reports counts `(0,0)`; after two memory + one parameter change the counts are `(1,2)`. |
| US-004 | HLR-004 | LLR-004.5 | TC-013 | U | 4 | pass | `test_unified_changeset.py` — an empty container reports empty; one memory change with no parameter change does not report empty. |
| US-004 | HLR-005 | LLR-005.1 | TC-015 | U | 5 | pass | `test_unified_write.py` — the written file is valid JSON re-parseable by `json.loads` with all four top-level keys (format identifier, version, parameter half, memory-field half); `serialize_unified` is byte-deterministic; an empty change-set still writes a valid document. |
| US-004 | HLR-005 | LLR-005.2 | TC-016 | U | 5 | pass | `test_unified_write.py` — a parameter entry round-trips `parameter_name` / `array_index` (incl. the `None` scalar/string shape) / `value`; the parameter half preserves insertion order; the three adversarial IEEE floats survive full binary64 precision. |
| US-004 | HLR-005 | LLR-005.3 | TC-017 | U | 5 | pass | `test_unified_write.py` — the memory half is a JSON array of objects, `address` is an integer-valued field never an object key (DD-10 / OQ-V1); a memory entry round-trips its exact integer `address` and exact ordered `new_bytes`; the memory half preserves insertion order. |
| US-004 | HLR-005 | LLR-005.4 | TC-018 | U | 5 | pass | `test_unified_write.py` — the write target resolves under `.s19tool/workarea/`; a filename with path separators is contained; a name without `.json` gets one; an existing name is dedup-suffixed; no temp file is left behind; a containment rejection (monkeypatched-helper arm + real-reparse-point arm) and an `OSError` from the staged write (S57-02 closure arm) each surface a `ValidationIssue`, not an exception. |
| US-004 | HLR-006 | LLR-006.1 | TC-019, TC-025 | U, RT | 6, 9 | pass | `test_unified_read.py` — `make_unified_file` parses to a unified change-set with a populated parameter `ChangeList` and a populated `MemoryChangeList`; `test_unified_roundtrip.py` (TC-025) is the corroborating round-trip verdict. |
| US-004 | HLR-006, HLR-008 | LLR-006.2 | TC-020, TC-014, TC-035 | U | 6 | pass | `test_unified_rules.py` (TC-020) — a truncated/garbage file → one `MF-JSON-PARSE` error issue, no exception; `test_unified_read.py` (TC-014) — each wrong-shape document (`[]`, `42`, `{"foo":1}`) → one `MF-BAD-STRUCTURE` issue, empty change-set, no `KeyError`; (TC-035) — a deeply-nested document → one `MF-JSON-PARSE` issue, no escaping `RecursionError`. |
| US-004 | HLR-006 | LLR-006.3 | TC-021 | U | 6 | pass | `test_unified_read.py` — a valid path is resolved through `workspace.resolve_input_path` and read; an unresolvable path → one `MF-PATH-UNRESOLVED` error issue and opens no file (no-open spy). |
| US-004 | HLR-006, HLR-008 | LLR-006.4 | TC-022 | U, A | 6 | pass | `test_unified_read.py` — with the size-probe seam stubbed over the 256 MB `DEFAULT_COPY_SIZE_CAP_BYTES` cap, an oversized file is rejected before `json.load` (one `MF-SIZE-CAP` issue, empty change-set, no parse reached); an at-cap file is not rejected. `analysis`: the cap is the shared batch-03 constant. |
| US-004 | HLR-006, HLR-008 | LLR-006.5 | TC-037 | U | 6 | pass | `test_unified_read.py` — an over-entry-count-ceiling file (`MF_ENTRY_COUNT_CEILING = 100_000`) drops the overflow and keeps the rest with one `MF-ENTRY-LIMIT` issue; an over-run-length-ceiling file (`MF_RUN_LENGTH_CEILING = 1_048_576`) drops the one offending entry and keeps the rest; the message carries no raw bytes; neither raises. |
| US-005 | HLR-007 | LLR-007.1 | TC-028, TC-030 | U | 7 | pass | `test_unified_export.py` — `test_tc028_cdfx_write_routes_through_the_batch03_writer` confirms the `.cdfx` is produced by a call into the unchanged batch-03 `write_cdfx_to_workarea` (spy on the entry point); `test_tc030_batch03_cdfx_writer_module_is_byte_unchanged` confirms `cdfx/writer.py` byte-unchanged. |
| US-005 | HLR-007 | LLR-007.2 | TC-029 | U | 7 | pass | `test_unified_export.py` — the memory-field export file is valid JSON carrying a format identifier, a version and an array of objects (every entry's exact `address` and `new_bytes`); the export is byte-deterministic; the file resolves under `.s19tool/workarea/` (LLR-007.2 containment clause). |
| US-005 | HLR-007 | LLR-007.3 | TC-028, TC-030 | U | 7 | pass | `test_unified_export.py` — `test_tc030_export_yields_two_distinct_files_never_merged` confirms exactly two files (one `.cdfx`, one `.json`, distinct, never merged) under `.s19tool/workarea/`; `test_tc028_export_produces_a_cdfx_file_under_the_workarea` corroborates. |
| US-005 | HLR-007, HLR-008 | LLR-007.4 | TC-031 | U | 7 | pass | `test_unified_export.py` — every combined-result issue carries a per-half `artifact` tag (`param-half` / `memory-half`); a memory-half write rejection does not block the `.cdfx` file (cross-half collect-don't-abort); a memory-field `OSError` surfaces a `ValidationIssue`, not an exception (S57-02 closure arm). |
| US-005 | HLR-007 | LLR-007.5 | TC-036 | U | 7 | pass | `test_unified_export.py` (6 tests) — **A2L-loaded arm:** the export re-resolves the parameter `ChangeList` via the batch-03 `resolve_against_a2l` path (spy assertion), feeds the result to the CDFX writer. **No-A2L arm:** the export proceeds with one info issue and no raise, every parameter resolves `unresolved-no-a2l`, an empty A2L list is treated as no-A2L. Confirms the A-1-blocker fix. |
| US-004, US-005 | HLR-008 | LLR-008.1 | TC-023 | U | 6 | pass | `test_unified_rules.py` — each per-entry rule (`MF-NO-ADDRESS`, `MF-EMPTY-BYTES`, `MF-BYTE-RANGE`) flags exactly one entry and keeps the clean sibling entry (collect-don't-abort); the missing-`address` case does not raise `KeyError`; the byte-range issue carries no raw bytes. |
| US-004, US-005 | HLR-008 | LLR-008.2 | TC-024 | U | 6 | pass | `test_unified_rules.py` — a file with an unrecognised version token is read and produces exactly one info-level `MF-VERSION-UNKNOWN` issue; a known version produces no version issue. |
| US-004, US-005 | HLR-008 | LLR-008.3 | TC-022 (+ TC-006, TC-031 artifact tags) | U | 2, 6, 7 | pass | `test_unified_read.py` / `test_memory_validate.py` / `test_unified_export.py` — every memory-change / unified / memory-field finding is a `ValidationIssue` whose `artifact` identifies the producing concern (`memory-half` / `param-half` / `unified` / etc.) and whose `severity` round-trips through `css_class_for_severity` to a valid `sev-*` class. |
| US-001, US-003, US-004 | HLR-009 | LLR-009.1 | TC-032 | I | 8 | pass | `test_tui_memory_patch.py` — under `App.run_test()`, an added memory change appears as a memory table row; memory and parameter rows coexist (batch-03 parameter rows survive — RK-5); the memory row shows the hex value and the validation status. |
| US-001, US-004 | HLR-009 | LLR-009.2 | TC-033, TC-027 | I, INSP | 8, 9 | pass | `test_tui_memory_patch.py` — a memory edit updates only the targeted entry; a remove returns to the empty state; a bad memory address is reported, not raised; the §5.6 checklist (TC-027) confirms no JSON parse/serialize or model logic in `app.py` — the handler routes `add_memory` / `edit_memory` / `remove_memory` through `self._cdfx_service`. |
| US-004, US-005 | HLR-009 | LLR-009.3 | TC-034 | I | 8 | pass | `test_tui_memory_patch.py` — the export action writes both the `.cdfx` and the memory-field file; per-half issues surface on the status path; a unified save writes JSON under `.s19tool/workarea/`; a save-then-load round-trips both halves; a malformed unified load does not crash the screen. |

**Row count:** 37 traceability rows covering all 37 LLR and all 37 TC. LLRs covered by more than one TC (LLR-001.1, LLR-001.2, LLR-004.1, LLR-004.2, LLR-006.1, LLR-006.2, LLR-007.1, LLR-007.3, LLR-008.3, LLR-009.2) cite each covering TC on a single row. Every distinct US, HLR, LLR and TC is present at least once — see §3.

> **TC-028 / TC-030 catalogue-label note (non-defect, recorded for this docs sweep).** The §5.7 catalogue assigns TC-028 = "two distinct work-area files" (LLR-007.3) and TC-030 = "reuses the unchanged batch-03 CDFX writer" (LLR-007.1). The implemented test names label `test_tc028_*` for the CDFX-routing-through-the-batch-03-writer behaviour and `test_tc030_*` for the two-distinct-files behaviour — i.e. the two TC labels are swapped relative to the catalogue. Both behaviours are fully covered and green ([`04-validation.md`](../04-validation.md) §5); the `Covers LLR` column above reconciles each TC to both LLR-007.1 and LLR-007.3 so traceability is intact. This is a test-naming cosmetic mismatch, not a coverage gap.

---

## 2. Coverage summary

Counts folded from [`04-validation.md`](../04-validation.md) §0, §5, §6, §7.

| Metric | Value |
|--------|-------|
| Total user stories | 5 (US-001..US-005) |
| Covered user stories | 5 (100%) |
| Total HLR | 9 (HLR-001..HLR-009) |
| HLR with verdict `pass` | 9 (100%) |
| Total LLR | 37 |
| LLR with verdict `pass` | 37 (100%) |
| Total test cases | 37 (TC-001..TC-037) |
| TC pass | 37 (100%) |
| TC partial | 0 |
| TC fail (blocker) | 0 |
| TC fail (non-blocker) | 0 |
| §5.9 batch acceptance criteria (1..10) | 10 met / 0 not-met |
| Open blocker findings at the gate | 0 |
| pytest baseline at gate (full suite) | **762 passed / 0 failed / 3 xfailed / 2 skipped**; 27 snapshots passed |
| pytest baseline (memory / unified / export subset, 11 files) | 151 passed / 0 failed |
| pytest baseline (`-m snapshot`) | 27 snapshots passed; 27 passed / 740 deselected |
| Engine `git diff main` | empty — zero bytes changed across `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` |
| Batch-03 CDFX `writer.py` / `resolve.py` | byte-unchanged (SHA-256 pin, `test_cdfx_unchanged.py`); `changelist.py` / `reader.py` carry no batch-04 worktree edit |
| Phase 4 verdict | `pass-with-gaps` (0 blockers; 4 documentary/environmental gaps) |

### 2.1 Coverage by validation method

| Method | TC count | Notes |
|--------|----------|-------|
| test (unit) — U | 32 | Memory-change model, range validation, value display, unified container, JSON write/read, the `MF-*` rule set, selective export. |
| test (integration) — I | 3 | TC-032, TC-033, TC-034 — the extended Patch Editor driven via `App.run_test()` (the `test_tui_memory_patch.py` harness). |
| test (round-trip) — RT | 1 | TC-025 — write→read structural equality including the `Optional[int]` parameter key shape, the three adversarial IEEE floats and the `inside`/`partial`/`outside`/multi-byte memory half. |
| inspection — INSP | 1 | TC-027 — the §5.6 compose-not-subclass + `app.py`-clean checklist (also corroborated by `test_unified_changeset.py` and `test_cdfx_unchanged.py`). |
| analysis | (corroborating) | TC-022 (the `DEFAULT_COPY_SIZE_CAP_BYTES` shared-constant argument) — a corroborating method only, counted once above under the primary method. |
| **Total** | **37** | No retired TC this batch. |

### 2.2 Suite trajectory across Phase 3 increments

| Increment | Title | Suite total | Δ |
|-----------|-------|-------------|---|
| baseline | (batch-03 close) | 611 | — |
| 1 | Memory-change model + CV doc fixes | 631 | +20 |
| 2 | Memory-change validation against the loaded image | 650 | +19 |
| 3 | Memory-change value display | 662 | +12 |
| 4 | Unified change-set container | 674 | +12 |
| 5 | Unified change-set file write | 693 | +19 |
| 6 | Unified change-set file read + `MF-*` rule set | 712 | +19 |
| 7 | Selective export coordinator | 729 | +17 |
| 8 | Patch Editor UI extension | 745 | +16 |
| 9 | Round-trip + integration hardening | 762 | +17 |

The progression reconciles: the 9 increments take the suite from the 611 batch-03 baseline to **762 passed / 0 failed / 3 xfailed / 2 skipped, 27 snapshots passed** ([`04-validation.md`](../04-validation.md) §1.1). The memory / unified / export subset (11 test files — `test_memory_changelist.py`, `test_memory_display.py`, `test_memory_validate.py`, `test_unified_changeset.py`, `test_unified_write.py`, `test_unified_read.py`, `test_unified_roundtrip.py`, `test_unified_rules.py`, `test_unified_export.py`, `test_tui_memory_patch.py`, `test_cdfx_unchanged.py`) is **151 passed / 0 failed** ([`04-validation.md`](../04-validation.md) §1.2). The 3 xfails and 2 skips are pre-existing batch-01/02/03 baseline cases — not batch-04 cases, unchanged through all 9 increments. (The per-increment Δ figures are the increment-packet test-count progression; the 762 close and the 151-pass subset are the Phase-4 evidence figures.)

---

## 3. Detected gaps

> Incomplete rows, requirements without a TC, or open findings carrying into a follow-up batch.

**Traceability completeness: NO GAPS.** Every one of the 5 US, 9 HLR, 37 LLR and 37 TC is traced end-to-end in §1 and carries a Phase-4 `pass` verdict. The §5.7 reverse-traceability check reconciles: the LLR-by-HLR-group tally is 4 (001.x) + 5 (002.x) + 3 (003.x) + 5 (004.x) + 4 (005.x) + 5 (006.x) + 5 (007.x) + 3 (008.x) + 3 (009.x) = **37**; the catalogue holds **37 active test cases over 37 IDs (TC-001…TC-037), no reserved/unallocated slot — TC-014 is allocated to the `MF-BAD-STRUCTURE` case**. There is **no requirement without a validation method, no LLR without a passing TC, and no TC without a recorded verdict** — this satisfies §5.9 acceptance criteria #1 and #2 ([`04-validation.md`](../04-validation.md) §7).

The four items below are the `-with-gaps` qualifiers from the Phase-4 verdict ([`04-validation.md`](../04-validation.md) §8). **None is a correctness defect, none is a blocker, none gates the batch.** They are documentary / environmental / accepted-residual-risk items carried to Phase 5/6.

| ID | Type | Severity | Description | Disposition |
|----|------|----------|-------------|-------------|
| G-1 | Environmental — residual risk (RK-2) | medium | vCDM interop is asserted from Vector documentation, not tested against a live vCDM instance (no license, no sample). Batch-04 does not change the CDFX format — it reuses the byte-unchanged batch-03 writer (C-1). | Out of automated scope by design. The achievable criterion — "the parameter half exports through the unchanged batch-03 CDFX writer" — is verified by TC-028 / TC-030 / TC-036. Real vCDM round-trip stays a client-side manual check; flag it in the Phase-6 demo / hand-off notes. |
| G-2 | CI hygiene | low | `ruff check` / `ruff format --check` not executed for increments 1–9 — `ruff` not installed in the Phase-3/4 environment; each increment substituted `python -m py_compile` (all clean). | Deferred to CI. Mitigated — every batch-04 module compiles; the 151-pass subset and 762-pass full suite import and exercise every module. Recommended: run `ruff` in `.github/workflows/tui-ci.yml` before merge; no code change anticipated. (Carried over identically from batch-03 G-3.) |
| G-3 | Environmental | low | Manual real-terminal Patch Editor verification not performed — Phase-3/4 ran headless (`App.run_test()` / `pytest`). HLR-003 / HLR-009 carry a `demo` corroborating method whose artifact is produced in Phase 6, not a pass/fail gate. | Deferred. Mitigated — TC-032/033/034 drive the full screen → `app.py` handler → `CdfxService` → `cdfx` package → `DataTable` path under `App.run_test()`; the memory-row render, the address/new-bytes wiring, the unified save/load round-trip, the malformed-load no-crash and the selective-export action are all test-pinned. Recommended: Javier runs a ~10-minute manual pass before merge. |
| G-4 | Semantic breadth (increment-9 note) | low | The increment-9 S57-02 fix reuses the existing `MF-WRITE-CONTAINMENT` code for a plain `OSError` (e.g. `PermissionError`, full disk) raised by the staged-temp write — slightly broad: an I/O fault is not a containment-traversal fault. | Accepted, documented. The `OSError` type/detail is passed into the message so the fault stays diagnosable; the issue behaviour (one issue, no raise, correct per-artifact tag) is correct and tested (`test_tc018_oserror_from_staged_write_surfaces_issue_not_exception`, `test_tc031_memory_field_oserror_surfaces_issue_not_exception`). A dedicated `MF-WRITE-IO` code is an optional one-line follow-up for a future batch. |

**Other items recorded, no Phase 4 action ([`04-validation.md`](../04-validation.md) §8):**

- The **TC-028 / TC-030 test-name label swap** — the two `test_tc028_*` / `test_tc030_*` names are swapped relative to the §5.7 catalogue's TC-028/TC-030 titles; both behaviours are fully covered and green, the LLR traceability is intact (see the §1 note). A cosmetic rename, not a finding.
- The Phase-2 iteration-2 closure findings **CV-01** (TC-010 must assert the literal `.` placeholder) and **CV-02** (§5.2 HLR-008 row should list TC-020) were folded into Phase 3 increment 1: CV-01 is **closed** — `test_tc010_non_printable_byte_renders_as_the_exact_dot_placeholder` asserts the exact `0x2E` character; CV-02 is an editorial table fix with no test impact.

---

## 4. Changes from previous batch

This is **batch 4** of the s19_app dev-flow.

| Field | Value |
|-------|-------|
| Previous batch | `2026-05-21-batch-03` (functional Patch Editor + ASAM CDFX `.cdfx` read/write) |
| Carried-forward findings closed by this batch | None re-opened. The batch-03 RK-2 (vCDM interop unverified) carries forward unchanged as G-1 — batch-04 does not change the CDFX format. |
| `R-*` traceability rows added to the living `REQUIREMENTS.md` | **5 new `R-MEM-001`..`R-MEM-005`** (synthesized from the 9 HLR / 37 LLR / 37 TC of [`01-requirements.md`](../01-requirements.md) — see the living [`REQUIREMENTS.md`](../../../REQUIREMENTS.md), section "Memory-value editing / unified change-set / selective export (batch 2026-05-21-batch-04)"). |
| `R-*` rows superseded by this batch | None. Batch-04 is a peer addition; it removes or supersedes no prior row. The batch-03 `R-CDFX-005` / `R-CDFX-018` (the CDFX writer + containment path) are **reused unchanged** by `R-MEM-004`. |
| `R-*` rows protected and confirmed not regressed | The engine `R-*` set — `R-READ-*`, `R-PARSE-*`, `R-VAL-*`, `R-HEX-*`, `R-A2L-*` — is untouched (`git diff main` empty, [`04-validation.md`](../04-validation.md) §2). The batch-02 `R-TUI-021`..`R-TUI-037` rows and the batch-03 `R-CDFX-001`..`R-CDFX-018` rows are not regressed — `R-CDFX-016` (functional Patch Editor) is extended, not replaced; the batch-03 CDFX `writer.py` / `resolve.py` are byte-unchanged (SHA-256 pin); `changelist.py` / `reader.py` carry no worktree edit. |
| Engine status | Frozen — zero bytes changed across `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`. The memory / unified / export feature is purely additive (six new `s19_app/tui/cdfx/` modules — `memory.py`, `memory_validate.py`, `memory_display.py`, `changeset.py`, `unified_io.py`, `export.py` — plus `cdfx/__init__.py` re-exports, the `cdfx_service.py` extension and the `app.py` Patch Editor wiring). `ValidationIssue` is reused as-is with an `artifact` string tag — no model edit. |

---

## 5. Quick bidirectional mapping

### 5.1 By user story

- **US-001 (build a memory-change list)** → HLR-001 → LLR-001.1/001.2/001.3/001.4 → TC-001, TC-002, TC-003, TC-004
- **US-002 (validate memory changes against the loaded image)** → HLR-002 → LLR-002.1/002.2/002.3/002.4/002.5 → TC-005, TC-006, TC-007, TC-008
- **US-003 (hex / ASCII / decimal value display)** → HLR-003 → LLR-003.1/003.2/003.3 → TC-009, TC-010, TC-011
- **US-004 (one container + one file for both halves)** → HLR-004, HLR-005, HLR-006, HLR-008 → LLR-004.1..004.5, LLR-005.1..005.4, LLR-006.1..006.5, LLR-008.1..008.3 → TC-012..TC-027, TC-035, TC-037
- **US-005 (selective export)** → HLR-007 → LLR-007.1..007.5 → TC-028, TC-029, TC-030, TC-031, TC-036
- **US-001 / US-003 / US-004 / US-005 (Patch Editor memory-change management)** → HLR-009 → LLR-009.1/009.2/009.3 → TC-032, TC-033, TC-034

### 5.2 By code file

The memory / unified / export feature is six new modules inside the existing `s19_app/tui/cdfx/` package plus the `cdfx_service` extension plus the Patch Editor wiring. New files created this batch are marked **(new)**.

| Code file | LLR(s) / role | Increment | Test(s) |
|-----------|---------------|-----------|---------|
| `s19_app/tui/cdfx/__init__.py` | Narrow public import surface — **edit**: re-exports the new public symbols (`MemoryChange` / `MemoryChangeList` / `MemoryStatus` / `validate_memory_changes` / `format_memory_value` / `MemoryValueRendering` / `UnifiedChangeSet` / `serialize_unified` / `write_unified_to_workarea` / `read_unified` / `export_unified` / the `MF-*` codes); package docstring updated to note the memory-field / unified-change-set concern | 1–7 | (import surface; exercised by all batch-04 test files) |
| `s19_app/tui/cdfx/memory.py` **(new)** | LLR-001.1..001.4, LLR-002.5 — `MemoryStatus` (str-enum), `MemoryChange` (`address`, `new_bytes` tuple, `status`; `__post_init__` raises `ValueError` per LLR-002.5; `addressed_range` property), `MemoryChangeList` (address-keyed, insertion-ordered; `add` / `edit` / `remove` / `get` / `entries`) | 1 | `tests/test_memory_changelist.py` |
| `s19_app/tui/cdfx/memory_validate.py` **(new)** | LLR-002.1..002.4, LLR-008.3 — `validate_memory_changes` — `inside`/`partial`/`outside`/`unvalidated-no-image` status against `LoadedFile.ranges`, inter-entry overlap check, collect-don't-abort `ValidationIssue`s with address-only messages (`_range_status` / `_range_issue` / `_overlap_issues` helpers) | 2 | `tests/test_memory_validate.py` |
| `s19_app/tui/cdfx/memory_display.py` **(new)** | LLR-003.1..003.3 — `format_memory_value` → `MemoryValueRendering` (hex-primary / ASCII companion with the pinned `.` 0x2E placeholder / decimal companion); pure, never mutates the stored bytes | 3 | `tests/test_memory_display.py` |
| `s19_app/tui/cdfx/changeset.py` **(new)** | LLR-004.1..004.5 — `UnifiedChangeSet` composing one batch-03 `ChangeList` + one `MemoryChangeList`; per-half access, independent mutation, per-half counts, empty-state query | 4 | `tests/test_unified_changeset.py` |
| `s19_app/tui/cdfx/unified_io.py` **(new)** | LLR-005.1..005.4, LLR-006.1..006.5, LLR-008.1..008.3 — `serialize_unified` / `write_unified_to_workarea` / `read_unified`; the `MF-*` rule-code constants and the `MF_ENTRY_COUNT_CEILING` (100 000) / `MF_RUN_LENGTH_CEILING` (1 048 576) ceilings; `UNIFIED_FORMAT_ID = "s19app-unified-changeset"`, `UNIFIED_FORMAT_VERSION = "1.0"` | 5 (write), 6 (read) | `tests/test_unified_write.py`, `tests/test_unified_read.py`, `tests/test_unified_rules.py`, `tests/test_unified_roundtrip.py` |
| `s19_app/tui/cdfx/export.py` **(new)** | LLR-007.1..007.5 — `export_unified` → `ExportResult`: re-resolve the parameter half via `resolve_against_a2l`, call the **unchanged** `write_cdfx_to_workarea`, write the memory-field JSON via `write_memory_field_to_workarea` / `serialize_memory_field`, collect per-half issues tagged on `ValidationIssue.artifact` | 7 | `tests/test_unified_export.py` |
| `s19_app/tui/services/cdfx_service.py` | LLR-009.1..009.3 (orchestration arm) — **edit**: `CdfxService` extended with memory-change operations, `memory_rows()`, and unified `save_unified` / `load_unified` / `export_selective`; holds a `UnifiedChangeSet` | 8 | `tests/test_tui_memory_patch.py` |
| `s19_app/tui/screens_directionb.py` | LLR-009.1, 009.2 — **edit**: `PatchEditorPanel` extended with memory-change rows, the address + new-bytes inputs, add/edit/remove buttons, save/load/export-selective controls; the batch-03 parameter-change controls survive | 8 | `tests/test_tui_memory_patch.py` |
| `s19_app/tui/app.py` | LLR-009.2, 009.3 — **edit**: UI-state wiring only — `on_patch_editor_panel_action_requested` routes `add_memory` / `edit_memory` / `remove_memory` / `save_unified` / `load_unified` / `export` through `self._cdfx_service`; **no JSON parse/serialize, no model logic** (C-7 / TC-027) | 8 | `tests/test_tui_memory_patch.py` (TC-027 inspection) |
| `s19_app/tui/cdfx/writer.py`, `resolve.py` | LLR-007.1, 007.5 — **reused byte-unchanged**: `write_cdfx_to_workarea` (the CDFX parameter-half export) and `resolve_against_a2l` (the export-time re-resolution); SHA-256-pinned by `test_cdfx_unchanged.py` | — | `tests/test_cdfx_unchanged.py` (TC-027/TC-030), `tests/test_unified_export.py` |
| `s19_app/tui/cdfx/changelist.py`, `reader.py` | LLR-004.2, (constraint C-3) — **reused byte-unchanged**: the batch-03 parameter `ChangeList` (`ChangeListEntry` / `ChangeList` / `ResolutionStatus`) composed by `UnifiedChangeSet`; no worktree edit | — | `tests/test_unified_changeset.py` (TC-026), `tests/test_cdfx_unchanged.py` (TC-027) |
| `s19_app/tui/workspace.py` | LLR-005.4, 006.3, 006.4, 007.2 — **reused read-only**: `resolve_input_path` (load path), `copy_into_workarea` / `_path_traverses_reparse_point` / `DEFAULT_COPY_SIZE_CAP_BYTES` (write-path containment + 256 MB cap) | — | `tests/test_unified_write.py`, `tests/test_unified_read.py`, `tests/test_unified_export.py` |
| `s19_app/validation/model.py` | LLR-008.3 — **reused as-is**, zero bytes changed; every batch-04 finding is a `ValidationIssue` with an `artifact` string tag (`memory-half` / `param-half` / `unified` / etc.) on the model's existing free-form `artifact: str` field — no model edit needed | — | `tests/test_unified_rules.py` (TC-022) |
| `s19_app/core.py`, `hexfile.py`, `range_index.py`, `tui/a2l.py`, `tui/mac.py`, `validation/` | **frozen engine surface** — `git diff main` empty; `LoadedFile.ranges` is consumed read-only by `memory_validate.py` | — | engine test files unchanged from batch-03 |
| `tests/conftest.py` | **edit**: the §5.4 synthetic-fixture additions (`memory_change_factory`, `make_ranged_s19`, `unified_changeset_factory`, `make_unified_file`, `make_malformed_unified_file`, `make_rule_violation_unified_file`, `make_oversized_unified_file`, `make_deeply_nested_unified_file`, `make_over_ceiling_unified_file`; the reused `make_patch_a2l` / `change_list_factory`) — additive, programmatic, no static binary | 1–7 | (fixture infrastructure) |

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-05-21-batch-04` |
| Batch title | Memory-value editing + unified change-set + selective export |
| Branch | `dev-flow/batch-02-direction-b-restyle` @ `701a849` (the 9 batch-04 increments present as new/untracked source) |
| Closing date | Phase 4 validated `2026-05-22`; Phase 6 docs delivered `2026-05-22` |
| Total iterations | Phase 1: iteration 1 + iteration 2 closure · Phase 2: `pass` (0 blockers, 22 findings closed, CV-01/CV-02 folded into Phase 3) · Phase 3: 9 increments · Phase 4: 1 · Phase 5: 1 |
| Validation passed | yes — `pass-with-gaps` (0 blockers; 4 documentary/environmental gaps G-1..G-4) |
| pytest baseline at gate | 762 passed / 0 failed / 3 xfailed / 2 skipped; 27 snapshots passed (Windows 11, Python 3.12.7, pytest 8.4.2); memory / unified / export subset 151 passed / 0 failed; `-m snapshot` subset 27 passed / 0 failed |
| Engine freeze | verified — `git diff main` empty across `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`; the feature is purely additive new files |
| Batch-03 CDFX freeze | verified — `cdfx/writer.py` and `cdfx/resolve.py` byte-unchanged by SHA-256 pin (`test_cdfx_unchanged.py`); `changelist.py` / `reader.py` carry no batch-04 worktree edit (C-1, C-3) |
| Traceability completeness | NO GAPS — 5 US / 9 HLR / 37 LLR / 37 TC all traced and `pass` |
| `R-*` rows added to living `REQUIREMENTS.md` | 5 (`R-MEM-001`..`R-MEM-005`); no prior row superseded |
| Synced to Obsidian | (post-merge — `/dev-flow-sync-en` after PR close) |
