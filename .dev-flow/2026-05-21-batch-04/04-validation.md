# Validation — s19_app — 2026-05-21-batch-04

**Phase:** 4 — Validation
**Iteration:** 1
**Date:** 2026-05-22
**Batch:** batch-04 — memory-value editing + unified change-set + selective export
**Source artifacts under validation:** `.dev-flow/2026-05-21-batch-04/01-requirements.md` (§5 Validation Strategy + §5.9 acceptance criteria), `02-review.md` (Phase 2 iteration-1 + iteration-2 closure — 22 findings closed, CV-01/CV-02 folded into Phase 3 increment 1), `03-increments/increment-001.md` … `increment-009.md`, `increment-plan.md`
**Validator:** qa-reviewer agent
**Branch:** `dev-flow/batch-02-direction-b-restyle` @ `701a849` (working tree — the 9 batch-04 increments are present as new/untracked source under `s19_app/tui/cdfx/` — `memory.py`, `memory_validate.py`, `memory_display.py`, `changeset.py`, `unified_io.py`, `export.py` — plus edits to `cdfx/__init__.py` and `tui/services/cdfx_service.py` and the Patch Editor wiring in `app.py`; the batch-03 `cdfx/` package and the batch-02 restyle sit beneath it)
**Environment:** Windows 11 Pro 10.0.26200, Python 3.12.7, pytest 8.4.2, `textual-snapshot` 1.1.0, `syrupy` 4.8.0 (dev extra installed)

---

## 0. Summary

Phase 3 delivered 9 increments: the batch-04 memory layer inside `s19_app/tui/cdfx/` — `memory.py` (`MemoryChange` / `MemoryChangeList` / `MemoryStatus`), `memory_validate.py` (`validate_memory_changes`), `memory_display.py` (`format_memory_value` / `MemoryValueRendering`), `changeset.py` (`UnifiedChangeSet`), `unified_io.py` (the unified-file writer + reader + `MF-*` rule set), `export.py` (the selective-export coordinator) — plus the `cdfx/__init__.py` re-export surface, the `cdfx_service.py` extension, and the Patch Editor memory-change UI extension wired into `app.py`. Increments 5–7 carried a combined `security-reviewer` pass; increment 9 closed the security finding **S57-02** (an `OSError` from the staged-temp write escaping the containment-error catch) and recorded the `MF-WRITE-CONTAINMENT`-reused-for-OSError note.

Phase 4 re-executed the §5 validation strategy independently on a Windows host: the full `pytest -q` suite, the batch-04 memory/unified/export subset, the `-m snapshot` subset, the engine-untouched `git diff main`, the C-4 no-new-runtime-dependency check, the batch-03 byte-unchanged check, and the §5.6 inspection checklist for the `inspection`-method TC (TC-027).

The pytest baseline carried out of increment 9 — **762 passed / 0 failed / 3 xfailed / 2 skipped, 27 snapshots passed** — was reproduced exactly in this Phase 4 run with no drift. The batch-04 subset (11 test files) is **151 passed / 0 failed**. The `-m snapshot` subset is **27 passed / 0 failed**. The engine-untouched `git diff main` over `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` is **empty (zero bytes changed)**. The batch-03 `cdfx/writer.py` and `cdfx/resolve.py` are confirmed **byte-unchanged** (SHA-256 pin in `test_cdfx_unchanged.py`); `changelist.py` / `reader.py` carry no batch-04 worktree edit. All 37 test cases (TC-001…TC-037) have an asserting test that passes. All 9 HLR and 37 LLR verdict `pass`. All 10 §5.9 acceptance criteria are **met**.

| Metric | Value |
|---|---|
| Total TCs evaluated | 37 (TC-001 … TC-037) |
| TC pass | 37 |
| TC partial | 0 |
| TC fail (blocker) | 0 |
| TC fail (non-blocker) | 0 |
| HLR verdicts (9) | 9 pass · 0 partial · 0 fail |
| LLR verdicts (37) | 37 pass · 0 partial · 0 fail |
| §5.9 acceptance criteria | 10 of 10 met · 0 not-met |
| Open blocker findings at the gate | 0 |
| pytest result (full) | 762 passed / 2 skipped / 3 xfailed / 0 failed; 27 snapshots passed |
| pytest result (batch-04 subset) | 151 passed / 0 failed |
| pytest result (`-m snapshot`) | 27 snapshots passed; 27 passed / 740 deselected |

**Verdict: `pass-with-gaps`.** The suite is green, the engine is untouched, the batch-03 CDFX writer/resolver are byte-unchanged, every requirement and every acceptance criterion is satisfied by recorded evidence. **No blocker-level fail was found — no rollback to Phase 3 is forced.** The `-with-gaps` qualifier records four documentary / environmental gaps (no live vCDM round-trip — RK-2; `ruff` not installed for increments 1–9; manual real-terminal Patch Editor verification headless-only; the `MF-WRITE-CONTAINMENT`-reused-for-`OSError` semantic-breadth note from increment 9). None of the four is a correctness defect, none gates the batch, and all four were already disclosed in the requirements §6.3 risks or the increment packets — they carry to Phase 5/6, not re-opened.

---

## 1. pytest baseline

### 1.1 Full suite — `python -m pytest -q`

Executed at Phase 4 start against the worktree (Windows 11, Python 3.12.7, pytest 8.4.2):

```
--------------------------- snapshot report summary ---------------------------
27 snapshots passed.
762 passed, 2 skipped, 3 xfailed in 200.80s (0:03:20)
```

Match against the increment-9 closing baseline (`762 passed / 0 failed / 3 xfailed / 2 skipped, 27 snapshots passed`) — **identical, zero drift.** The orchestrator's brief stated the suite is green at 762 passed / 0 failed and asked for verification rather than assumption; the independent Phase 4 run **confirms** it — 762 passed, 0 failed. The 0-failed result holds.

### 1.2 Batch-04 memory / unified / export subset

`python -m pytest -q` over the 11 batch-04 test files (`test_memory_changelist.py`, `test_memory_display.py`, `test_memory_validate.py`, `test_unified_changeset.py`, `test_unified_write.py`, `test_unified_read.py`, `test_unified_roundtrip.py`, `test_unified_rules.py`, `test_unified_export.py`, `test_tui_memory_patch.py`, `test_cdfx_unchanged.py`):

```
151 passed in 8.35s
```

145 `def test_*` functions across the 11 files, 151 collected items after parametrization (the `make_rule_violation_unified_file` per-`MF-*`-rule variants and the `make_over_ceiling_unified_file` two-arm generator parametrize beyond the bare function count). **0 failed.**

Per-file `def test_*` counts: `test_memory_changelist.py` 20 · `test_memory_display.py` 12 · `test_memory_validate.py` 19 · `test_unified_changeset.py` 12 · `test_unified_write.py` 19 · `test_unified_read.py` 12 · `test_unified_roundtrip.py` 9 · `test_unified_rules.py` 7 · `test_unified_export.py` 17 · `test_tui_memory_patch.py` 16 · `test_cdfx_unchanged.py` 2 = 145.

### 1.3 Snapshot subset — `python -m pytest -q -m snapshot`

```
--------------------------- snapshot report summary ---------------------------
27 snapshots passed.
27 passed, 740 deselected in 26.22s
```

The 27-baseline `textual-snapshot` matrix re-matches its committed `.svg` baselines with no diff. batch-04 is a data-layer + screen-wiring batch; it added no new snapshot baseline (the `patch-comfortable-120x30` cell still renders the Patch Editor screen and passes). The §5 strategy assigns no snapshot TC to batch-04 — the Patch Editor memory-change behaviour is verified by `App.run_test()` integration tests (TC-032, TC-033, TC-034), not by SVG baselines — so the 27 passing cells are a no-regression confirmation for the batch-02 layer.

### 1.4 The 3 `xfail` rows and 2 skips

The 3 documented `xfail` rows and the 2 skips are pre-existing baseline cases inherited from batch-01/02/03 (unchanged through all 9 batch-04 increments — each increment packet records "2 skipped + 3 xfailed unchanged (pre-existing)"). They are **not** batch-04 cases and carry no batch-04 finding. No unexpected `xpass` was observed.

Per §5.9 #3 / the dev-flow Hard rule: an unexpected pytest failure at error/blocker severity would be a `blocker`. **None observed → no Phase 4 blocker.**

---

## 2. Engine-untouched check (§5.9 #9 / task brief)

The task brief asks for an engine-untouched `git diff --stat main` over `core.py` / `hexfile.py` / `range_index.py` / `validation/` / `tui/a2l.py` / `tui/mac.py`, and a confirmation that the batch-03 `cdfx/writer.py` + `resolve.py` are byte-unchanged.

**`git diff --stat main` over the engine surface** (run in Phase 4):

```
git diff --stat main -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py s19_app/tui/a2l.py s19_app/tui/mac.py
[empty output]   EXIT:0

git diff --stat main -- s19_app/validation
[empty output]   EXIT:0
```

**Result: zero bytes changed across all engine modules** — `core.py`, `hexfile.py`, `range_index.py`, the entire `validation/` directory, `tui/a2l.py`, `tui/mac.py`. Constraint C-2 (engine/parsers consumed read-only) holds at the strictest level. The batch-04 memory-change validator (`memory_validate.py`) consumes the loaded-image ranges through the `LoadedFile.ranges` snapshot — read-only — and does not re-parse or modify any firmware file (C-8, DD-9 honored). The `validation/model.py` `ValidationIssue` model is reused as-is; no model edit was needed — every batch-04 finding passes the existing model an `artifact` string tag (`memory-half` / `param-half` / etc.) on the model's existing free-form `artifact: str` field (C-5).

**Batch-03 CDFX writer / resolver byte-unchanged.** `test_cdfx_unchanged.py::test_tc027_batch03_cdfx_modules_are_byte_unchanged` pins `s19_app/tui/cdfx/writer.py` and `s19_app/tui/cdfx/resolve.py` by SHA-256 against their increment-7 batch-03 baseline; the test is **green** in this Phase 4 run. (These two files do not exist on `main` — they are batch-03 additions on this branch — so a `git diff main` cannot express "unchanged since batch-03"; the content-hash pin is the correct mechanism.) Additionally, the Phase 4 worktree-vs-staged `git diff` over `writer.py` / `resolve.py` / `changelist.py` / `reader.py` / `display.py` is **empty** — batch-04 introduced no working-tree edit to any batch-03 CDFX module. Constraints C-1 (reuse the CDFX writer unchanged) and C-3 (`changelist.py` / `reader.py` unchanged) hold.

**The batch-04 feature is purely additive.** `git status` confirms the six new batch-04 modules — `s19_app/tui/cdfx/memory.py`, `memory_validate.py`, `memory_display.py`, `changeset.py`, `unified_io.py`, `export.py` — and the 8 new `tests/test_memory_*.py` / `test_unified_*.py` / `test_tui_memory_patch.py` / `test_cdfx_unchanged.py` files are **new, untracked**. The only batch-04 modifications to tracked-or-staged files are `cdfx/__init__.py` (re-exports only — adds the new public symbols, edits no batch-03 logic), `tui/services/cdfx_service.py` (the service extension), `tests/conftest.py` (the §5.4 fixture additions — additive; the one deletion line is an import-statement reshuffle, not logic removal) and `app.py` (the Patch Editor memory-change wiring).

**Verdict — engine untouched: PASS.** The engine / parser / validation suites are byte-identical to `main`; the batch-03 CDFX writer/resolver are byte-identical to their batch-03 baseline; the no-regression criterion holds at the strictest level.

---

## 3. C-4 no-new-runtime-dependency check (§5.9 #9 / TC-027)

`git diff main -- pyproject.toml` and `git diff main -- requirements.txt` were run in Phase 4.

`requirements.txt` — **empty diff, zero change.**

`pyproject.toml` — the only diff vs `main` is the **batch-02** change (already validated in batch-02 and batch-03): the runtime `[project] dependencies` array holds **exactly `rich>=13.0` and `textual>=8.0.2`** — the `textual>=8.0.2` lower-bound floor is a batch-02 edit, not a new dependency (the dependency *set* is `{rich, textual}` on both sides). `pytest-textual-snapshot==1.1.0` lives only in `[project.optional-dependencies] dev` — a dev-only extra, explicitly commented in the file as "NEVER added to `[project]` dependencies — it does not affect the `s19tui` runtime footprint". The `snapshot` pytest marker is likewise a batch-02 addition. **No line of the `pyproject.toml` diff is attributable to batch-04.**

**The batch-04 feature added no dependency at all.** Every file read/write this batch performs — the unified change-set file and the memory-field export file — uses the Python standard library `json` module only (constraint C-4, DD-1). Unlike the batch-03 XML path, `json` has no entity-expansion / DOCTYPE / external-entity surface, so the billion-laughs / `SYSTEM`-entity test cases of batch-03 have no batch-04 equivalent and are correctly absent. **C-4: PASS.**

---

## 4. Inspection-checklist result — TC-027 (§5.6 → LLR-004.2, LLR-009.2)

TC-027 is the one `inspection`-method TC. The §5.6 checklist was applied in Phase 4 against the live tree and is corroborated by the asserting tests in `test_cdfx_unchanged.py` (TC-027) and `test_unified_changeset.py` (TC-026, the runtime compose-not-subclass corroboration).

| §5.6 checklist item | Result | Evidence |
|---|---|---|
| `cdfx/changelist.py` and `cdfx/reader.py` byte-unchanged (C-3); the unified container holds a `ChangeList` by **composition**, not as a base class | PASS | Phase 4 worktree-vs-staged `git diff` over `changelist.py` / `reader.py` is empty. `test_tc026_unified_change_set_is_not_a_subclass` asserts `UnifiedChangeSet` is not a `ChangeList`/`MemoryChangeList` subclass; `test_tc026_halves_are_instances_of_the_existing_list_types` asserts the halves are held as members. |
| `cdfx/writer.py` byte-unchanged (C-1) — confirmed jointly with TC-030 | PASS | §2 above — `test_tc027_batch03_cdfx_modules_are_byte_unchanged` SHA-256-pins `writer.py` (and `resolve.py`), green; `test_tc030_batch03_cdfx_writer_module_is_byte_unchanged` corroborates. |
| No JSON parse/serialize call and no memory-change / unified-change-set / export model logic in `app.py`; `app.py` holds only UI-state wiring calling the service | PASS | Phase 4 grep over `app.py`: no `MemoryChange` / `UnifiedChangeSet` / `serialize_unified` / `read_unified` reference. The only `import json` + `json.dumps` calls in `app.py` are pre-existing batch-02/03 code (project-save payload line 575, A2L-export line 1677) — unrelated to the change-set feature. `on_patch_editor_panel_action_requested` routes `add_memory` / `edit_memory` / `remove_memory` / `save_unified` / `load_unified` / `export` through `self._cdfx_service` (app.py lines 1212–1242). |
| The memory-change model, unified container, unified JSON read/write and the selective-export coordinator live in dedicated service-style modules inside `s19_app/tui/cdfx/` | PASS | `s19_app/tui/cdfx/` holds the six new one-concern-per-module files (`memory.py`, `memory_validate.py`, `memory_display.py`, `changeset.py`, `unified_io.py`, `export.py`); `cdfx_service.py` is the service seam. No change-set / JSON logic in `app.py` (C-7, §6.2.1 OQ-5). |
| New public functions carry the `PROJECT_RULES.md` docstring section order + type hints (C-6) — spot-checked | PASS | Spot-checked `memory.py`, `unified_io.py`, `export.py`: public functions carry type hints and the Summary→Args→Returns→Raises→Data Flow→Dependencies→Example docstring order consistent with the `tui/a2l.py` / `hexview.py` / batch-03 `cdfx/` baseline. Not exhaustively re-audited — the §5.6 checklist specifies "spot-checked, not exhaustively". |
| No new runtime dependency in `pyproject.toml` (C-4); `requirements.txt` unchanged — every read/write uses stdlib `json` | PASS | §3 above — `requirements.txt` zero diff; `pyproject.toml` carries no batch-04 diff; runtime dependency set unchanged at `{rich, textual}`. |

**All six §5.6 checklist items pass → TC-027 PASS.**

---

## 5. Per-TC pass/fail table

Verdict legend: `pass` = an asserting test is green in this Phase 4 run / the inspection checklist is fully satisfied. Every TC verdict below is backed by the §1.2 (151-pass) and §1.1 (762-pass) Phase 4 evidence runs. Each TC was confirmed to have ≥1 referencing asserting test in the 11 batch-04 test files (every TC-NNN ID TC-001…TC-037 was grep-confirmed present); the "Evidence" column names the test file(s) and the LLR coverage. Method abbreviations match §5.7: U = test (unit), I = test (integration), RT = test (round-trip), INSP = inspection, A = analysis (corroborating only).

| TC | Title | Covers LLR | Method | Verdict | Evidence (Phase 4) |
|----|-------|------------|--------|---------|--------------------|
| TC-001 | Memory-change entry construction | LLR-001.1 | U | pass | `test_memory_changelist.py` — entry reports `address` / `new_bytes` / status; status defaults to `unvalidated-no-image`; `new_bytes` preserves order/length and is stored as an immutable tuple; the addressed range is the half-open `(address, address+len)` span. Green in the 151-pass run. |
| TC-002 | Add / edit / remove + identity de-duplication | LLR-001.2, 001.3 | U | pass | `test_memory_changelist.py` — add-then-remove empties the list; edit touches only the target entry; re-adding the same `address` updates in place (no duplicate) and preserves insertion position; edit/remove of a missing address raises `KeyError`. |
| TC-003 | Deterministic memory-change ordering | LLR-001.4 | U | pass | `test_memory_changelist.py` — two serializations of the same list produce identical entry order; `entries` is a defensive copy, not the backing store. |
| TC-004 | Memory-change list — HLR-001 model coherence | LLR-001.1, 001.2 | U | pass | `test_memory_changelist.py` — a built/edited/queried list reports a consistent entry set; the factory overlap pair stays two distinct entries (distinct `address` keys not collapsed by the LLR-001.3 identity rule). |
| TC-005 | Validate an entry against the loaded image ranges | LLR-002.1 | U | pass | `test_memory_validate.py` — against a `make_ranged_s19` `LoadedFile`: whole-run-inside → `inside`; run crossing a range end → `partial`; run in the inter-range gap → `outside`; the gap-spanning run (starts in range 1, crosses the gap, ends in range 2) receives the single status `partial`; the validator reads `LoadedFile.ranges`, no firmware re-parse. |
| TC-006 | Out-of-range / partial entries collect a warning, never abort | LLR-002.2 | U | pass | `test_memory_validate.py` — `outside`, `partial` and the gap-spanning entry each collect exactly one warning `ValidationIssue`; an `inside` entry collects none; the validator never raises; the issue message omits the raw `new_bytes` content (C-9 / S-006). |
| TC-007 | Validation without a loaded image | LLR-002.3 | U | pass | `test_memory_validate.py` — with no image (and with an empty-ranges image) every entry is marked `unvalidated-no-image`; an empty list with no image returns no issues; no exception. |
| TC-008 | Inter-entry overlap and malformed-`new_bytes` rejection | LLR-002.4, 002.5 | U | pass | `test_memory_validate.py` + `test_memory_changelist.py` — **overlap arm:** the factory overlap pair (`0x100 len 8` + `0x104 len 8`, distinct keys) each collect exactly one overlap warning, addresses match the pinned constant, non-overlapping entries collect none, message omits raw bytes. **`ValueError` arms:** constructing an entry with a byte `256`, a negative byte, or an empty `new_bytes` run each raises `ValueError`; the malformed run is also rejected via `MemoryChangeList.add` / `.edit`. |
| TC-009 | Hex display of the stored bytes | LLR-003.1 | U | pass | `test_memory_display.py` — `[0x01,0xAB,0xFF]` renders `01 AB FF` (uppercase, two-digit, space-separated); small bytes pad to two digits; a single byte renders with no separator. |
| TC-010 | ASCII and decimal companion renderings | LLR-003.2 | U | pass | `test_memory_display.py` — `[0x41,0x42]` renders ASCII `AB` and decimal `65 66`; a non-printable byte renders as the **exact `.` placeholder (0x2E)** — `test_tc010_non_printable_byte_renders_as_the_exact_dot_placeholder` asserts the literal character, closing the Phase 2 closure finding CV-01; ASCII keeps one-char-per-byte alignment; the 0x20 and 0x7E range boundaries render as characters; all three forms are returned in a `MemoryValueRendering`. |
| TC-011 | Display derivation does not mutate stored bytes | LLR-003.3 | U | pass | `test_memory_display.py` — stored `new_bytes` is byte-identical before and after every rendering call; repeated rendering is stable and non-mutating; a caller-supplied list is not mutated. |
| TC-012 | Unified change-set holds both halves | LLR-004.1 | U | pass | `test_unified_changeset.py` — `UnifiedChangeSet` exposes its parameter `ChangeList` and `MemoryChangeList` as distinct, independently-accessible attributes; the parameter half carries no `ResolutionResult` (resolution-free container, A-7 / LLR-004.1). |
| TC-013 | Independent mutation, per-half counts, empty-state | LLR-004.3, 004.4, 004.5 | U | pass | `test_unified_changeset.py` — an empty container reports counts `(0,0)` and empty; mutating the memory half leaves the parameter half unchanged and vice versa; after two memory + one parameter change the counts and empty-state are correct; one memory change alone is not empty. |
| TC-014 | Well-formed-but-wrong-shape JSON emits `MF-BAD-STRUCTURE` | LLR-006.2 | U | pass | `test_unified_read.py` — each wrong-shape document (`[]`, `42`, `{"foo":1}`) produces exactly one error-level `MF-BAD-STRUCTURE` `ValidationIssue`, an empty unified change-set, and raises no exception — in particular no `KeyError`; the document is confirmed parseable JSON (the failure is shape, not syntax). |
| TC-015 | Unified file JSON structure | LLR-005.1 | U | pass | `test_unified_write.py` — the written file is valid JSON re-parseable by `json.loads` with all four top-level keys (format identifier, version, parameter half, memory-field half); `serialize_unified` is byte-deterministic; an empty change-set still writes a valid document. |
| TC-016 | Unified file encodes each parameter entry | LLR-005.2 | U | pass | `test_unified_write.py` — a parameter entry round-trips `parameter_name` / `array_index` (incl. the `None` scalar/string shape) / `value`; the parameter half preserves insertion order; the three adversarial IEEE floats survive full binary64 precision. |
| TC-017 | Unified file encodes each memory-field entry | LLR-005.3 | U | pass | `test_unified_write.py` — the memory half is a JSON array of objects, `address` is an integer-valued field never an object key (DD-10 / OQ-V1); a memory entry round-trips its exact integer `address` and exact ordered `new_bytes`; the memory half preserves insertion order. |
| TC-018 | Unified file write is work-area-contained | LLR-005.4 | U | pass | `test_unified_write.py` — the write target resolves under `.s19tool/workarea/`; a filename with path separators is contained; a name without `.json` gets one; an existing name is dedup-suffixed; no temp file is left behind after a clean write; a containment rejection surfaces a `ValidationIssue` not an exception (via the monkeypatched-helper arm and the real-reparse-point arm); an `OSError` from the staged write surfaces a `ValidationIssue` not an exception (S57-02 closure arm). |
| TC-019 | Unified file reader parses both halves | LLR-006.1 | U | pass | `test_unified_read.py` — `make_unified_file` parses to a unified change-set with a populated parameter `ChangeList` and a populated `MemoryChangeList`; the reader recovers the exact parameter and memory content. |
| TC-020 | Unified file reader tolerates malformed JSON | LLR-006.2 | U | pass | `test_unified_rules.py` — a truncated/garbage JSON file → exactly one `MF-JSON-PARSE` error `ValidationIssue`, no exception; the parse-issue message carries no file bytes (C-9). |
| TC-021 | Unified file reader path resolution | LLR-006.3 | U | pass | `test_unified_read.py` — a valid path is resolved through `workspace.resolve_input_path` and read; an unresolvable path yields exactly one error `ValidationIssue` and opens no file (no-open spy). |
| TC-022 | Read-path size bound | LLR-006.4 | U, A | pass | `test_unified_read.py` — with the size-probe seam stubbed over the 256 MB `DEFAULT_COPY_SIZE_CAP_BYTES` cap, an oversized file is rejected before `json.load` (one `MF-SIZE-CAP` issue, empty change-set, no parse reached); an at-cap file is not rejected. `analysis`: the cap is the shared batch-03 constant. |
| TC-023 | Memory-field structural rule violations emit `MF-*` issues | LLR-008.1 | U | pass | `test_unified_rules.py` — each per-entry rule (`MF-NO-ADDRESS`, `MF-EMPTY-BYTES`, `MF-BYTE-RANGE`) flags exactly one entry and keeps the clean sibling entry (collect-don't-abort); the missing-`address` case does not raise `KeyError`; the byte-range issue carries no raw bytes. |
| TC-024 | Unknown file version is tolerated | LLR-008.2 | U | pass | `test_unified_rules.py` — a file with an unrecognised version token is read and produces exactly one info-level `MF-VERSION-UNKNOWN` issue; a known version produces no version issue. |
| TC-025 | Unified-file round-trip — write then read recovers the change-set | RT | pass | `test_unified_roundtrip.py` (9 tests) — a `UnifiedChangeSet` (scalar + 1-D array + ASCII + the three adversarial IEEE floats parameter half, `inside`+`partial`+`outside`+multi-byte memory half) survives write→read **structurally equal**: every parameter value by **exact `==`, no float tolerance**; adversarial floats survive full binary64 precision; insertion order preserved in both halves; every memory byte run recovered exactly; round-trip holds for every memory variant; counts match. The validation/resolution status is **re-derived on read** and asserted separately (the §5.5 / Q-06 pinned predicate). |
| TC-026 | Unified change-set composes the two existing list types | LLR-004.1, 004.2 | U | pass | `test_unified_changeset.py` — the halves are instances of the batch-03 `ChangeList` and the `MemoryChangeList` held by composition; `UnifiedChangeSet` is not a subclass; mutating one half through the container leaves the other; the factory composes both source factories. Runtime corroboration of the TC-027 inspection clause. |
| TC-027 | Compose-not-subclass and `app.py`-clean inspection | INSP | pass | §4 above — all six §5.6 checklist items pass; `test_cdfx_unchanged.py` (engine modules unchanged vs `main`; batch-03 CDFX modules byte-unchanged by SHA-256 pin) green. |
| TC-028 | Selective export — CDFX file produced via the batch-03 writer | LLR-007.1 (+007.3) | U | pass | `test_unified_export.py` — `test_tc028_export_produces_a_cdfx_file_under_the_workarea` and `test_tc028_cdfx_write_routes_through_the_batch03_writer` confirm the `.cdfx` is produced by a call into the unchanged batch-03 `write_cdfx_to_workarea` (spy on the entry point), under `.s19tool/workarea/`. |
| TC-029 | Selective export produces the memory-field JSON file | LLR-007.2 | U | pass | `test_unified_export.py` — the memory-field export file is valid JSON carrying a format identifier, a version and an array of objects (every entry's exact `address` and `new_bytes`); the export is byte-deterministic; the file resolves under `.s19tool/workarea/` (LLR-007.2 containment clause). |
| TC-030 | Selective export — two distinct work-area files / writer byte-unchanged | LLR-007.1, 007.3 | U | pass | `test_unified_export.py` — `test_tc030_export_yields_two_distinct_files_never_merged` confirms exactly two files (one `.cdfx`, one `.json`, distinct, never merged); `test_tc030_batch03_cdfx_writer_module_is_byte_unchanged` confirms `cdfx/writer.py` is byte-unchanged. |
| TC-031 | Selective export collects and reports each half's issues | LLR-007.4 | U | pass | `test_unified_export.py` — every combined-result issue carries a per-half `artifact` tag; parameter-half issues are tagged `param-half`; a memory-half write rejection does not block the `.cdfx` file (cross-half collect-don't-abort); a memory-field `OSError` surfaces a `ValidationIssue` not an exception (S57-02 closure arm). |
| TC-032 | Patch Editor renders the memory-change list | I | pass | `test_tui_memory_patch.py` — under `App.run_test()`, an added memory change appears as a memory table row; memory and parameter rows coexist (batch-03 parameter rows survive — RK-5); the memory row shows the hex value and the validation status. |
| TC-033 | Patch Editor memory-change controls are wired | I | pass | `test_tui_memory_patch.py` — a memory edit updates only the targeted entry; a remove returns to the empty state; a bad memory address is reported, not raised; a unified save writes JSON under `.s19tool/workarea/`; a save-then-load round-trips both halves; a malformed unified load does not crash the screen. |
| TC-034 | Patch Editor save / load / selective-export actions | I | pass | `test_tui_memory_patch.py` — the export action writes both the `.cdfx` and the memory-field file; per-half issues surface on the status path. (Save/load round-trip and malformed-load no-crash also covered by the TC-033 arms above.) |
| TC-035 | Deeply-nested JSON does not escape as `RecursionError` | U | pass | `test_unified_read.py` — `make_deeply_nested_unified_file` fed to the reader produces exactly one `MF-JSON-PARSE` error issue, an empty change-set, and no escaping `RecursionError` — the reader catches `RecursionError` (a `RuntimeError`), not only `json.JSONDecodeError` (LLR-006.2 / S-002 closure). |
| TC-036 | Selective export re-resolves the parameter half | U | pass | `test_unified_export.py` (6 tests) — **A2L-loaded arm:** the export re-resolves the parameter `ChangeList` via the batch-03 `resolve_against_a2l` path (spy assertion), the re-resolution result feeds the CDFX writer, the resolved parameter is written into the `.cdfx`. **No-A2L arm:** the export proceeds with one info issue and no raise, every parameter resolves `unresolved-no-a2l`, an empty A2L list is treated as no-A2L. Confirms the A-1-blocker fix LLR-007.5. |
| TC-037 | Read-path decoded-structure ceiling emits `MF-ENTRY-LIMIT` | U | pass | `test_unified_read.py` — an over-entry-count-ceiling file drops the overflow and keeps the rest with one `MF-ENTRY-LIMIT` issue; an over-run-length-ceiling file drops the one offending entry and keeps the rest; the `MF-ENTRY-LIMIT` message carries no raw bytes; neither raises (LLR-006.5 / S-001 closure). |

**Roll-up:** 37 TCs · **37 pass** · 0 partial · 0 fail. Every one of TC-001…TC-037 maps to ≥1 asserting test that is green in the Phase 4 151-pass / 762-pass runs.

> **TC-028 / TC-030 catalogue-label note (non-defect).** The §5.7 catalogue assigns TC-028 = "two distinct work-area files" (LLR-007.3) and TC-030 = "reuses the unchanged batch-03 CDFX writer" (LLR-007.1). The implemented test names label `test_tc028_*` for the CDFX-routing-through-the-batch-03-writer behaviour and `test_tc030_*` for the two-distinct-files behaviour — i.e. the two TC labels are swapped relative to the catalogue. **Both behaviours are fully covered and green** (`test_tc028_cdfx_write_routes_through_the_batch03_writer`, `test_tc030_export_yields_two_distinct_files_never_merged`, `test_tc030_batch03_cdfx_writer_module_is_byte_unchanged`, `test_tc028_export_produces_a_cdfx_file_under_the_workarea`); the `Covers LLR` column above reconciles each TC to both LLR-007.1 and LLR-007.3 so traceability is intact. This is a test-naming cosmetic mismatch, not a coverage gap — recorded for the Phase 6 docs sweep, not a finding.

---

## 6. Per-requirement verdict

### 6.1 High-level requirements (9)

| HLR | Title | Verdict | Evidence |
|-----|-------|---------|----------|
| HLR-001 | Memory-change model | pass | TC-001, TC-002, TC-003, TC-004 — entry structure, add/edit/remove + identity de-duplication, deterministic ordering, model coherence. |
| HLR-002 | Memory-change validation against the loaded image ranges | pass | TC-005, TC-006, TC-007, TC-008 — `inside`/`partial`/`outside`/`unvalidated-no-image` status, the gap-spanning single-`partial` case, collect-don't-abort warnings, inter-entry overlap, malformed-`new_bytes` rejection. |
| HLR-003 | Memory-change value display | pass | TC-009, TC-010, TC-011 — hex / ASCII / decimal rendering, the pinned `.` placeholder, the no-mutation invariant. (`demo` corroboration deferred to Phase 6, not a gate.) |
| HLR-004 | Unified change-set container | pass | TC-012, TC-013, TC-026, TC-027 — per-half access, independent mutation, per-half counts, empty-state, compose-not-subclass. |
| HLR-005 | Unified change-set file write | pass | TC-015, TC-016, TC-017, TC-018, TC-025 — JSON structure, parameter/memory entry encoding, work-area containment, round-trip corroboration. |
| HLR-006 | Unified change-set file read | pass | TC-014, TC-019, TC-020, TC-021, TC-022, TC-025, TC-035, TC-037 — parse both halves, malformed/mis-shaped/deeply-nested/mis-pathed/oversized/over-ceiling files, round-trip corroboration. |
| HLR-007 | Selective export to CDFX + memory-field JSON | pass | TC-028, TC-029, TC-030, TC-031, TC-036 — CDFX via the unchanged batch-03 writer, the memory-field JSON file, the two-file split, cross-half issue collection, export-time re-resolution. |
| HLR-008 | Memory-field file validation rule set | pass | TC-014, TC-020, TC-022, TC-023, TC-024, TC-035, TC-037 — every `MF-*` code provoked with documented code/severity. |
| HLR-009 | Patch Editor memory-change management | pass | TC-032, TC-033, TC-034 — render/edit/remove/save/load/export driven through `App.run_test()`; the batch-03 parameter controls survive (RK-5). (`demo` corroboration deferred to Phase 6.) |

**9 HLR · 9 pass · 0 partial · 0 fail.**

### 6.2 Low-level requirements (37)

| LLR | Verdict | TC / evidence | LLR | Verdict | TC / evidence |
|-----|---------|---------------|-----|---------|---------------|
| LLR-001.1 | pass | TC-001, TC-004 | LLR-006.1 | pass | TC-019, TC-025 |
| LLR-001.2 | pass | TC-002, TC-004 | LLR-006.2 | pass | TC-020, TC-014, TC-035 |
| LLR-001.3 | pass | TC-002 | LLR-006.3 | pass | TC-021 |
| LLR-001.4 | pass | TC-003 | LLR-006.4 | pass | TC-022 |
| LLR-002.1 | pass | TC-005 | LLR-006.5 | pass | TC-037 |
| LLR-002.2 | pass | TC-006 | LLR-007.1 | pass | TC-028, TC-030 |
| LLR-002.3 | pass | TC-007 | LLR-007.2 | pass | TC-029 |
| LLR-002.4 | pass | TC-008 (overlap arm) | LLR-007.3 | pass | TC-028, TC-030 |
| LLR-002.5 | pass | TC-008 (`ValueError` arms) | LLR-007.4 | pass | TC-031 |
| LLR-003.1 | pass | TC-009 | LLR-007.5 | pass | TC-036 |
| LLR-003.2 | pass | TC-010 | LLR-008.1 | pass | TC-023 |
| LLR-003.3 | pass | TC-011 | LLR-008.2 | pass | TC-024 |
| LLR-004.1 | pass | TC-012, TC-026 | LLR-008.3 | pass | TC-022 (+ TC-006/031 artifact tags) |
| LLR-004.2 | pass | TC-027, TC-026 | LLR-009.1 | pass | TC-032 |
| LLR-004.3 | pass | TC-013 | LLR-009.2 | pass | TC-033, TC-027 |
| LLR-004.4 | pass | TC-013 | LLR-009.3 | pass | TC-034 |
| LLR-004.5 | pass | TC-013 | | | |
| LLR-005.1 | pass | TC-015 | | | |
| LLR-005.2 | pass | TC-016 | | | |
| LLR-005.3 | pass | TC-017 | | | |
| LLR-005.4 | pass | TC-018 | | | |

**37 LLR · 37 pass · 0 partial · 0 fail.** The LLR-by-HLR-group tally reconciles with §1.5 / §4 of the requirements: 4 (001.x) + 5 (002.x) + 3 (003.x) + 5 (004.x) + 4 (005.x) + 5 (006.x) + 5 (007.x) + 3 (008.x) + 3 (009.x) = **37**. Every LLR maps to ≥1 passing TC; the per-LLR↔TC cross-check matches the §5.7 reverse-traceability table exactly.

---

## 7. §5.9 batch acceptance criteria

| # | Criterion (abridged) | Verdict | Evidence |
|---|----------------------|---------|----------|
| 1 | **Coverage** — 100% of the 9 HLR + 37 LLR map to ≥1 TC with a recorded `pass`; the §5.7 catalogue of 37 active TCs over 37 IDs (TC-001…TC-037) is the record. | **met** | §5 + §6 — 9 HLR + 37 LLR all map to TCs; 37/37 TCs pass. All 37 TC-NNN IDs were grep-confirmed present in the 11 batch-04 test files. |
| 2 | **Method assigned** — no HLR or LLR left without a validation method. | **met** | §5.2 / §5.3 of the requirements are complete; every TC in §5 carries its method (U / I / RT / INSP / A). |
| 3 | **No blocker fails** — zero failing TCs at error/blocker severity. | **met** | §1 — 0 failed in the full 762-pass run and the 151-pass subset; §5 — 0 TC fails of any severity. No warning-level finding to justify. |
| 4 | **Round-trip pass** — TC-025 passes: a scalar + 1-D array + ASCII + three adversarial IEEE floats parameter half plus an `inside`+`partial`+`outside`+multi-byte memory half survives write→read structurally equal, exact float `==`, exact ordered byte sequence. | **met** | TC-025 — `test_unified_roundtrip.py`, 9 tests green; exact `==` on every parameter value, adversarial floats survive full binary64 precision, every memory byte run recovered exactly, order preserved, status re-derived and asserted separately (Q-06 predicate). |
| 5 | **Rule-code completeness** — every `MF-*` structural code provoked by a TC with the documented code/severity (TC-014, TC-020, TC-022, TC-023, TC-024, TC-035, TC-037); Phase 2 confirmed the rule-code set is fixed and documented. | **met** | Phase 4 grep over `unified_io.py` / `export.py` / `memory_validate.py` confirms all 9 spec `MF-*` codes present — `MF-JSON-PARSE`, `MF-BAD-STRUCTURE`, `MF-NO-ADDRESS`, `MF-EMPTY-BYTES`, `MF-BYTE-RANGE`, `MF-VERSION-UNKNOWN`, `MF-SIZE-CAP`, `MF-ENTRY-LIMIT`, `MF-PATH-UNRESOLVED` — plus the write-path code `MF-WRITE-CONTAINMENT`. Each is exercised by TC-014 / TC-020 / TC-022 / TC-023 / TC-024 / TC-035 / TC-037 / TC-018 / TC-021. The Phase 2 iteration-2 closure confirmed the set fixed and documented (HLR-008). |
| 6 | **Collect-don't-abort honored** — every read-error TC (TC-014, TC-020, TC-022, TC-023, TC-035, TC-037) and the malformed-load arm of TC-034 confirm the reader returns issues without an uncaught exception — incl. no `KeyError` (TC-014) and no `RecursionError` (TC-035); TC-006 / TC-007 confirm the same for the memory-change validator. | **met** | All named TCs green in §5. TC-014 asserts no escaping `KeyError`; TC-035 asserts no escaping `RecursionError` (the reader catches the `RuntimeError`-subclass explicitly); TC-023 asserts the clean sibling entry is recovered; `test_tc033_malformed_unified_load_does_not_crash_the_screen` covers the TC-034 malformed-load arm; `test_tc006_validator_never_raises` / TC-007 cover the validator. |
| 7 | **Selective-export split** — TC-028 (two distinct work-area files), TC-030 (`.cdfx` via the unchanged batch-03 writer), TC-036 (export-time re-resolution, both arms), TC-031 (independent export + cross-half issue reporting). | **met** | TC-028/TC-030/TC-031/TC-036 all green in §5 (note the cosmetic TC-028/TC-030 label swap recorded in §5 — both behaviours covered). TC-030 confirms `writer.py` byte-unchanged; TC-036 confirms the LLR-007.5 re-resolution that closed the A-1 blocker. |
| 8 | **Containment and resource bounds** — TC-018 (work-area-contained writes), TC-029 (memory-field file under `.s19tool/workarea/`), TC-021 (load-path resolution), TC-022 (256 MB on-disk cap), TC-037 (decoded-structure ceiling), TC-035 (deeply-nested `RecursionError` catch); Phase 2 security-reviewer signed off on the path-handling and resource-bound surface. | **met** | TC-018/TC-021/TC-022/TC-029/TC-035/TC-037 all green in §5. The Phase 2 iteration-2 closure records the security-reviewer verdict `all-closed-clean` — S-001 (decoded-structure ceiling → LLR-006.5), S-002 (`RecursionError` → LLR-006.2), S-003 (memory-field write-path clause → LLR-007.2), S-004/S-005/S-006 all closed. The increments 5–7 combined security pass plus the increment-9 S57-02 closure (the `OSError`-escapes-containment-catch fix) are recorded in the increment packets and confirmed by `test_tc018_oserror_from_staged_write_surfaces_issue_not_exception` + `test_tc031_memory_field_oserror_surfaces_issue_not_exception`. |
| 9 | **No new dependency** — TC-027's §5.6 checklist confirms `pyproject.toml` / `requirements.txt` unchanged (C-4) and `changelist.py`, `reader.py`, `writer.py` byte-unchanged (C-1, C-3). | **met** | §3 + §4 — `requirements.txt` zero diff; `pyproject.toml` carries no batch-04 diff (the only diff is batch-02); runtime dependency set unchanged at `{rich, textual}`. `writer.py` / `resolve.py` SHA-256-pinned byte-unchanged; `changelist.py` / `reader.py` carry no batch-04 worktree edit. |
| 10 | **Synthetic fixtures only** — every firmware-image / `.cdfx` / unified-file / memory-field-file / change-list fixture is synthetic (constraint C-9). | **met** | The §5.4 generators (`memory_change_factory`, `make_ranged_s19`, `unified_changeset_factory`, `make_unified_file`, `make_malformed_unified_file`, `make_rule_violation_unified_file`, `make_oversized_unified_file`, `make_deeply_nested_unified_file`, `make_over_ceiling_unified_file`, the reused `make_patch_a2l` / `change_list_factory`) are programmatic, in `tests/conftest.py`; no static `.cdfx` / unified-file / firmware binary on disk. No client artifact appears in `tests/`. The C-9 reinforcement (issue messages must not echo raw `new_bytes`) is tested by TC-006 / TC-008 / TC-023 / TC-037 message-content assertions. |

**10 of 10 acceptance criteria met. 0 not-met.**

---

## 8. Gaps

Four gaps are recorded. **None is a correctness defect, none is a blocker, none gates the batch.** All four were already disclosed in the requirements §6.3 open risks or the increment packets; they are listed here for the Phase 5 post-mortem / Phase 6 docs sweep, not re-opened as findings.

### Gap 1 — vCDM interop unverified (RK-2)
**Severity:** medium (residual risk). **Status:** open — out of automated scope by design.
vCDM (Vector Calibration Data Management) is the target consumer of the `.cdfx` produced by the selective-export parameter half. Batch-04 does not change the CDFX format — it reuses the byte-unchanged batch-03 writer (C-1, confirmed §2) — so compatibility is exactly the batch-03 position: asserted from Vector documentation, not tested against a live vCDM instance (no license, no sample available). The achievable automated criterion is "the parameter half exports through the unchanged batch-03 CDFX writer" — which TC-028 / TC-030 / TC-036 verify. **Mitigation:** the CDFX writer is byte-identical to its batch-03 baseline; the selective-export coordinator only feeds it a freshly re-resolved `ResolutionResult`. **Recommendation:** a real vCDM round-trip stays a client-side manual check — flag it in the Phase 6 demo script / hand-off notes. Not a testability gap to close this batch.

### Gap 2 — `ruff check` / `ruff format --check` not executed for increments 1–9
**Severity:** low (CI hygiene). **Status:** open — deferred to CI.
`ruff` is not installed in the Phase 3 / Phase 4 environment; the increment packets record substituting `python -m py_compile` on each changed Python file (all clean) as the pending substitute. **Mitigation:** every batch-04 module compiles; the 151-pass batch-04 subset and the 762-pass full suite import and exercise every module. The unguarded surface is lint-style only (import order, unused names, formatting). **Recommendation:** run `ruff check .` / `ruff format --check .` in CI or a ruff-equipped environment before merge — the project CI (`.github/workflows/tui-ci.yml`) is the natural home; no code change is anticipated. (Carried over identically from the batch-03 Gap 3.)

### Gap 3 — Manual real-terminal Patch Editor verification not performed (headless environment)
**Severity:** low (documentary). **Status:** open — deferred.
All Phase 3 verification and this Phase 4 run are headless (`App.run_test()` / `pytest`). HLR-003 and HLR-009 carry a `demo` corroborating method whose artifact is produced in Phase 6, not a pass/fail gate. This Phase 4 environment cannot launch an interactive terminal session, so the manual eyeball pass over the memory-change Patch Editor extension was **not** executed here. **Mitigation:** TC-032 / TC-033 / TC-034 drive the full screen → `app.py` handler → `CdfxService` → `cdfx` package → `DataTable` path under `App.run_test()`; the memory-row render, the address/new-bytes input wiring, the unified save/load round-trip, the malformed-load no-crash and the selective-export action are all test-pinned, and the batch-03-parameter-controls-survive clause (RK-5) is asserted by `test_tc032_memory_and_parameter_rows_coexist`. The residual unguarded surface is subjective real-terminal aesthetics only. **Recommendation:** Javier runs a ~10-minute manual pass before merge — `s19tui --load examples/case_00_public/prg.s19`, open the Patch Editor, add/edit/remove a memory change, observe the hex/ASCII/decimal rendering and the `inside`/`partial`/`outside` status, save and load a unified `.json`, trigger the selective export. Optional, not gate-critical given the integration coverage.

### Gap 4 — `MF-WRITE-CONTAINMENT` reused for a plain `OSError` (increment-9 note)
**Severity:** low (semantic breadth). **Status:** open — accepted, documented.
The increment-9 S57-02 fix added an `except OSError` arm to `write_unified_to_workarea` and `write_memory_field_to_workarea` so a fault from the staged-temp write (e.g. a `PermissionError`, or a full disk) surfaces as one `ValidationIssue` rather than escaping the collect-don't-abort contract. The fix reuses the existing `MF-WRITE-CONTAINMENT` code for that issue — which is slightly broad: a full disk is an I/O fault, not a containment-traversal fault. The increment-9 packet records this explicitly: a dedicated `MF-WRITE-IO` code was considered and rejected as scope creep, the `OSError` type/detail is passed into the message so the fault stays diagnosable, and the issue *behaviour* (one issue, no raise, correct per-artifact tag) is correct and tested (`test_tc018_oserror_from_staged_write_surfaces_issue_not_exception`, `test_tc031_memory_field_oserror_surfaces_issue_not_exception`, both green). **Recommendation:** if a future batch wants a precise `MF-WRITE-IO` code distinct from `MF-WRITE-CONTAINMENT`, that is a one-line follow-up — the increment-9 packet already flags it for the Phase 4 security review's optional consideration. Not a correctness defect; the collect-don't-abort guarantee holds.

**Other items recorded, no Phase 4 action:**
- **TC-028 / TC-030 test-name label swap** (recorded in §5) — the two `test_tc028_*` / `test_tc030_*` names are swapped relative to the §5.7 catalogue's TC-028/TC-030 titles; both behaviours are fully covered and green, the LLR traceability is intact. A cosmetic rename for the Phase 6 docs sweep, not a finding.
- The Phase 2 iteration-2 closure findings **CV-01** (TC-010 must assert the literal `.` placeholder) and **CV-02** (§5.2 HLR-008 row should list TC-020) were folded into Phase 3 increment 1: CV-01 is **closed** — `test_tc010_non_printable_byte_renders_as_the_exact_dot_placeholder` asserts the exact `0x2E` character (verified green in §5); CV-02 is an editorial table fix in the requirements doc with no test impact.

---

## 9. Verdict and recommendation

**Verdict: `pass-with-gaps`.**

The Phase 4 gate is satisfied:
- The full `pytest -q` suite is **green — 762 passed / 0 failed / 3 xfailed / 2 skipped, 27 snapshots passed** — reproduced in this Phase 4 run with zero drift from the increment-9 baseline. The orchestrator's brief stated the suite is green at 762/0 and asked for verification rather than assumption; the independent run **confirms** it.
- The batch-04 subset (11 test files) is **151 passed / 0 failed**; the `-m snapshot` subset is **27 passed / 0 failed**.
- The engine-untouched `git diff main` over `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` is **empty (zero bytes changed)** — the batch-04 feature is purely additive new files; §5.9 #9 and constraint C-2 hold at the strictest level.
- The batch-03 `cdfx/writer.py` and `cdfx/resolve.py` are confirmed **byte-unchanged** by a SHA-256 pin; `changelist.py` / `reader.py` carry no batch-04 worktree edit — constraints C-1 / C-3 hold.
- The C-4 no-new-runtime-dependency check is **confirmed** — `requirements.txt` zero diff, `pyproject.toml` carries no batch-04 diff, runtime dependency set unchanged at `{rich, textual}`, every file read/write uses stdlib `json`.
- **All 37 TCs pass** (TC-001…TC-037). 0 partial, 0 fail.
- **All 9 HLR and 37 LLR verdict `pass`.** 0 partial, 0 fail.
- **All 10 §5.9 acceptance criteria are met.** 0 not-met — including the round-trip gate (TC-025 exact float `==`), the rule-code-completeness gate (all 9 `MF-*` codes provoked), the containment/resource-bound gate (TC-018/021/022/035/037 + the Phase 2 security-reviewer `all-closed-clean` sign-off + the increment-9 S57-02 closure), and the C-4 / C-9 / no-regression gates.
- **Zero blocker-severity fails** — §5.9 #3 satisfied. The dev-flow Phase 4 rollback rule fires only on an open blocker; **there is none.**

**No rollback to Phase 3 is forced or warranted.** As the orchestrator's brief anticipated, the suite is green (762 passed / 0 failed) and the engine-untouched + batch-03-byte-unchanged + no-new-dependency checks were verified independently — no blocker was found.

The four `-with-gaps` items (vCDM interop unverified — RK-2; `ruff` not installed for increments 1–9; manual real-terminal Patch Editor verification not run in this headless environment; the `MF-WRITE-CONTAINMENT`-reused-for-`OSError` semantic-breadth note from increment 9) are all documentary / environmental / accepted items already surfaced in the requirements §6.3 risks or the increment packets. None is a correctness defect, none gates the batch.

**Recommended next step:** advance to **Phase 5 (post-mortem)**. The four gaps are carried forward — Gap 2 (`ruff` in CI) and Gap 3 (manual Patch Editor pass) are quick pre-merge actions for Javier; Gap 1 (live vCDM round-trip) stays client-side and cannot be closed inside this batch; Gap 4 (`MF-WRITE-IO` code) is an optional one-line follow-up for a future batch. The increment 5–7 combined security-reviewer pass and the increment-9 S57-02 closure are discharged by this Phase 4 pass: the containment/resource-bound acceptance criterion (§7 #8) records the Phase 2 security-reviewer `all-closed-clean` closure plus the S57-02 `OSError`-handling fix, and this document is the qa-reviewer acceptance-criteria verdict. No code or test change is required to close the Phase 4 gate.

---

*Generated by the qa-reviewer agent — Phase 4 validation of batch-04 (memory-value editing + unified change-set + selective export). All test output in this document is from Phase 4 evidence runs on the Windows host (Windows 11, Python 3.12.7, pytest 8.4.2) at branch `dev-flow/batch-02-direction-b-restyle` @ `701a849` with the 9 batch-04 increments present in the working tree.*
