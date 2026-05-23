# Increment Plan — s19_app — batch-04

**Phase:** 3 — Implementation (planning)
**Batch:** 2026-05-21-batch-04 — memory-field change kind + unified change-set + selective export
**Source contract:** [`01-requirements.md`](../01-requirements.md) — 5 US / 9 HLR / **37 LLR / 37 TC**
**Phase 2 closure:** [`02-review.md`](../02-review.md) — 0 open blockers; CV-01 + CV-02 doc fixes folded into increment 1
**Baseline:** branch `dev-flow/batch-02-direction-b-restyle`; full suite **611 passed / 2 skipped / 3 xfailed / 0 failed** (batch-03 state)

---

## 0. Summary

- **Total increments: 9.**
- Each increment touches **≤5 files**, ships a runnable app, and ends with a green `pytest -q`.
- Every increment is dependency-ordered: a later increment only consumes modules built earlier.
- The arc follows the requirements' own suggested flow: model → validation → display → container → write → read → export → UI → round-trip/integration.
- Increment 1 also folds in the two Phase-2 closure doc fixes **CV-01** (TC-010 must assert the exact `.` placeholder) and **CV-02** (the §5.2 HLR-008 row must list TC-020).

### Per-increment one-line scope

| # | Title | One-line scope |
|---|-------|----------------|
| 1 | Memory-change model + CV doc fixes | `MemoryChange` / `MemoryChangeList` data model (add/edit/remove, address identity, deterministic order, `ValueError` on malformed bytes); fold CV-01 + CV-02 into `01-requirements.md`. |
| 2 | Memory-change validation against the loaded image | `validate_memory_changes` — `inside`/`partial`/`outside`/`unvalidated-no-image` status against `LoadedFile.ranges`, inter-entry overlap check, collect-don't-abort `ValidationIssue`s with address-only messages. |
| 3 | Memory-change value display | `format_memory_value` — hex-primary (uppercase two-digit space-separated), ASCII companion with the pinned `.` placeholder, decimal companion; no mutation of stored bytes. |
| 4 | Unified change-set container | `UnifiedChangeSet` composing a batch-03 `ChangeList` + a `MemoryChangeList`; per-half access, independent mutation, per-half counts, empty-state query. |
| 5 | Unified change-set file write | `write_unified_to_workarea` — JSON document (format-id + version + both halves, memory half as the LLR-005.3 array-of-objects), serialize-to-temp-then-`copy_into_workarea` containment. |
| 6 | Unified change-set file read + `MF-*` rule set | `read_unified` — parse both halves, the full `MF-*` rule set (`MF-JSON-PARSE`, `MF-BAD-STRUCTURE`, `MF-NO-ADDRESS`, `MF-EMPTY-BYTES`, `MF-BYTE-RANGE`, `MF-VERSION-UNKNOWN`, `MF-SIZE-CAP`, `MF-ENTRY-LIMIT`, `MF-PATH-UNRESOLVED`), `RecursionError` catch, size cap, decoded-structure ceiling, `resolve_input_path`. |
| 7 | Selective export coordinator | `export_unified` — re-resolve the parameter half via `resolve_against_a2l`, call the **unchanged** `write_cdfx_to_workarea`, write the memory-field JSON file, collect per-half issues tagged on `ValidationIssue.artifact`. |
| 8 | Patch Editor UI extension | Extend `PatchEditorPanel` + `CdfxService` with memory-change rows/controls and save/load/selective-export actions; `app.py` holds UI-state wiring only. |
| 9 | Round-trip + integration tests | TC-025 adversarial-float/byte-run round-trip; TC-032/033/034 headless integration tests; final suite-green confirmation and TC-027 inspection-checklist sign-off. |

---

## A. Module placement decision

**Decision: extend the existing `s19_app/tui/cdfx/` package — no new sibling package.**

Rationale, consistent with the `core` / `tui` separation and §6.2.1 OQ-5:

- `01-requirements.md` §2.1 states explicitly that batch-04 *"extends that same package"* and *"does not open a new architectural layer — it is a peer addition inside `s19_app/tui/cdfx/`"*. §6.2.1 OQ-5 bakes the same decision (`memory.py`, `changeset.py`, `unified_io.py`, `export.py` inside `cdfx/`).
- The `core` layer (`core.py`, `hexfile.py`) is consumed **read-only** (constraint C-2). The memory-change model is a TUI-side *edit-intent* artifact — it belongs beside the parameter `ChangeList`, which already lives in `cdfx/`, not in `core`.
- The batch-03 `cdfx/` package is already the established "fourth concern beside the parsers" (§2.1). Adding a memory-change peer there keeps one import surface (`from s19_app.tui.cdfx import ...`) and one `cdfx_service` orchestration layer — no new top-level convention (constraint C-7, the `CLAUDE.md` TUI-layer rule).
- The `cdfx/` package name is now slightly broader than "CDFX" — but renaming the package would violate "surgical changes" and touch every importer. The package docstring is updated (increment 1) to record that it now also holds the memory-field / unified-change-set concern; the directory name stays.

**New modules added to `s19_app/tui/cdfx/`:**

| Module | Purpose | Introduced in |
|--------|---------|---------------|
| `memory.py` | `MemoryChange` entry + `MemoryChangeList` collection + `MemoryStatus` enum (the memory-change model). | Increment 1 |
| `memory_validate.py` | `validate_memory_changes` — range validation against `LoadedFile`, overlap check. | Increment 2 |
| `memory_display.py` | `format_memory_value` — hex / ASCII / decimal renderings. | Increment 3 |
| `changeset.py` | `UnifiedChangeSet` container composing `ChangeList` + `MemoryChangeList`. | Increment 4 |
| `unified_io.py` | Unified-file JSON writer + reader + the `MF-*` rule set. | Increments 5 (write) & 6 (read) |
| `export.py` | `export_unified` — the selective-export coordinator. | Increment 7 |

`cdfx_service.py` (in `tui/services/`) is **extended**, not replaced, in increment 8 — it gains memory-change and unified-file/export operations beside its existing parameter-change `add_entry`/`save`/`load`. `s19_app/tui/cdfx/__init__.py` re-exports each new public symbol so the import surface stays narrow.

**Files that stay byte-unchanged this batch** (constraints C-1, C-2, C-3): `cdfx/changelist.py`, `cdfx/reader.py`, `cdfx/writer.py`, `cdfx/resolve.py`, `cdfx/display.py`, `core.py`, `hexfile.py`, `validation/*`, `workspace.py`, `tui/a2l.py`, `tui/mac.py`. They are imported and called, never edited.

---

## B. Increment 1 — Memory-change model + CV doc fixes (FULL DETAIL)

### B.1 Number & title
Increment 1 — Memory-change model + Phase-2 closure doc fixes.

### B.2 Goal
Build the pure data layer of the memory-change kind: a structured, address-keyed entry record and an ordered collection with add/edit/remove and identity dedup, malformed-byte rejection at construction, and a deterministic iteration order. This is the raw-memory peer of the batch-03 `ChangeList` and the foundation every later increment composes. Also fold the two Phase-2 closure doc fixes into the requirements document.

### B.3 LLRs covered
- **LLR-001.1** — Memory-change entry data structure (`address`, `new_bytes`, validation-status field; addressed range `(address, address+len(new_bytes))`).
- **LLR-001.2** — Add / edit / remove operations.
- **LLR-001.3** — Entry identity is `address`; a re-add updates in place, no duplicate.
- **LLR-001.4** — Deterministic ordering (pinned by a test) so repeated serialization is byte-identical.
- **LLR-002.5** — Malformed `new_bytes` (a byte negative, a byte `> 255`, or an empty run) rejected at construction with `ValueError`. *(Construction-time validation lives in the model module; the collect-don't-abort validator of LLR-002.1–.4 is increment 2.)*

### B.4 TCs covered
- **TC-001** — Memory-change entry construction (fields, order/length preserved, addressed range exposed).
- **TC-002** — Add / edit / remove and identity de-duplication (add-then-remove leaves empty; edit touches only the target; same `address` twice yields one entry, latest bytes).
- **TC-003** — Deterministic memory-change ordering (two serializations → identical entry order).
- **TC-004** — HLR-001 model-coherence roll-up (build + edit + query → consistent entry set).
- **TC-008 — `ValueError` arms only** — constructing with byte `256`, a negative byte, or an empty `new_bytes` run each raises `ValueError`. *(TC-008's overlap arm is increment 2.)*

### B.5 Files (≤5)

| # | File | Purpose |
|---|------|---------|
| 1 | `s19_app/tui/cdfx/memory.py` | **New.** `MemoryStatus` (str-enum: `inside` / `partial` / `outside` / `unvalidated-no-image`), `MemoryChange` dataclass (`address`, `new_bytes`, `status`; `__post_init__` raises `ValueError` per LLR-002.5; `addressed_range` property), `MemoryChangeList` collection (`add` / `edit` / `remove` / `get` / `entries` / `__len__`, address-keyed `dict` for insertion-order determinism — mirrors `ChangeList`). |
| 2 | `s19_app/tui/cdfx/__init__.py` | **Edit.** Re-export `MemoryChange`, `MemoryChangeList`, `MemoryStatus`; update the package docstring to note the package now also holds the memory-field / unified-change-set concern. |
| 3 | `tests/conftest.py` | **Edit.** Add the `memory_change_factory` generator (per §5.4): inside / partial / outside / gap-spanning / overlap-pair variants, pinned addresses (`0x100 len 8` + `0x104 len 8` for the overlap pair). Address validation against ranges is exercised from increment 2; increment 1 uses the factory's bare-list build path for TC-001…TC-004. |
| 4 | `tests/test_memory_changelist.py` | **New.** TC-001…TC-004 and the TC-008 `ValueError` arms. |
| 5 | `.dev-flow/2026-05-21-batch-04/01-requirements.md` | **Edit.** Fold in CV-01 (TC-010 row / §5.7 catalogue: assert the exact `.` 0x2E placeholder — LLR-003.2 already pins it; align the TC wording) and CV-02 (§5.2 HLR-008 row must list TC-020 alongside TC-014/022/023/024/035/037). |

*Note on the file cap:* `conftest.py` is shared test infrastructure; adding one factory there is the established batch-03 pattern (`change_list_factory`). The 5-file count holds. If the `memory_change_factory` turns out to need `make_ranged_s19` as a hard dependency at this stage, defer the range-coupled variants to increment 2 (they are only *consumed* there) to keep the count — increment 1's factory only needs the bare-list build path.

### B.6 Dependencies
None. This is the root increment — pure data, no Textual, no I/O, no `core` consumption. It only imports stdlib (`dataclasses`, `enum`, `typing`).

### B.7 Risks
- **Ordering choice.** LLR-001.4 lets the implementation pick insertion-order *or* ascending-address; it must pin the choice with a test. **Mitigation:** mirror `ChangeList` exactly — an insertion-ordered `dict` keyed on `address`. TC-003 pins it. Stating "same as batch-03" removes the ambiguity.
- **`new_bytes` storage type.** Stored as a sequence of `int` (0–255), per LLR-001.1. A `bytes`/`bytearray` would also satisfy it but JSON round-trip (increment 5/6) and the LLR-005.3 array-of-integers wire shape make a plain `list[int]` (or an immutable `tuple[int, ...]`) the cleaner choice. **Mitigation:** pick `tuple[int, ...]` for the stored field (immutability supports LLR-003.3 "display never mutates"); `__post_init__` coerces and validates. Decide and document in the module docstring.
- **Editing the requirements doc.** CV-01/CV-02 are minor editorial fixes; the risk is touching normative text by accident. **Mitigation:** the two edits are confined to the §5.2 table row and the TC-010 / §5.7 catalogue wording — no HLR/LLR `Statement:` bullet is touched. Diff-review the change.

### B.8 Exit criteria
- `pytest -q` green: 611 baseline + the new `test_memory_changelist.py` cases, 0 failures.
- App still launches (`s19tui` imports cleanly — the new module is import-only, not wired into a screen yet).
- CV-01 and CV-02 visible in `01-requirements.md`; no normative statement altered.

---

## C. Increments 2–9 — scope, LLRs, TCs, files, dependencies, risks

### Increment 2 — Memory-change validation against the loaded image

- **LLRs:** LLR-002.1 (inside/partial/outside status, gap-spanning → single `partial`), LLR-002.2 (collect-don't-abort warning per partial/outside, address-only message — no raw `new_bytes`), LLR-002.3 (`unvalidated-no-image` with no image loaded), LLR-002.4 (inter-entry overlap check), LLR-008.3 (findings are `ValidationIssue`, severity round-trips through `css_class_for_severity`).
- **TCs:** TC-005, TC-006, TC-007, TC-008 (overlap arm).
- **Files (≤5):**
  1. `s19_app/tui/cdfx/memory_validate.py` — **new.** `validate_memory_changes(memory_list, loaded_file) -> list[ValidationIssue]`: stamps each entry's `MemoryStatus` against `LoadedFile.ranges`, emits one warning per partial/outside entry and one per overlapping-entry pair; messages reference `address` + a byte-count summary only (constraint C-9 / S-006).
  2. `s19_app/tui/cdfx/__init__.py` — **edit.** Re-export `validate_memory_changes`.
  3. `tests/conftest.py` — **edit.** Add `make_ranged_s19` (two disjoint gap-separated ranges via the existing `_s19_data_record` helpers, loaded through `load_service` to a real `LoadedFile`); wire the range-coupled `memory_change_factory` variants if deferred from increment 1.
  4. `tests/test_memory_validate.py` — **new.** TC-005, TC-006, TC-007, TC-008 (overlap arm).
  5. *(reserve)* `tests/test_memory_changelist.py` — **edit** only if the TC-008 overlap arm is better co-located with the existing TC-008 `ValueError` arms; otherwise unused.
- **Dependencies:** increment 1 (`MemoryChange`/`MemoryChangeList`/`MemoryStatus`). Consumes `LoadedFile` read-only and `range_index.py` membership primitives.
- **Risks:** RK-4 (`S19File` vs `IntelHexFile` range parity) — mitigated by validating against the `LoadedFile.ranges` snapshot, never branching on file type. The gap-spanning "single `partial`, single issue" rule (OQ-V2 / A-3) is subtle — the validator must compute the addressed range's relationship to *all* ranges once and emit one verdict; TC-005/TC-006 pin it. Use `range_index` binary search rather than a linear scan (`CLAUDE.md` guidance) since many addresses are checked against many ranges.

### Increment 3 — Memory-change value display

- **LLRs:** LLR-003.1 (hex-primary: uppercase two-digit space-separated), LLR-003.2 (ASCII companion with the pinned `.` 0x2E placeholder for any byte outside 0x20–0x7E; decimal companion space-separated), LLR-003.3 (rendering never mutates stored `new_bytes`).
- **TCs:** TC-009, TC-010, TC-011.
- **Files (≤5):**
  1. `s19_app/tui/cdfx/memory_display.py` — **new.** `format_memory_value(new_bytes) -> MemoryValueRendering` (or three functions `hex_render` / `ascii_render` / `decimal_render`) — pure, no mutation. Mirrors the style of `cdfx/display.py` but driven by raw bytes, not an A2L type.
  2. `s19_app/tui/cdfx/__init__.py` — **edit.** Re-export the display entry point.
  3. `tests/test_memory_display.py` — **new.** TC-009 (`[0x01,0xAB,0xFF]` → `01 AB FF`), TC-010 (`[0x41,0x42]` → ASCII `AB` / decimal `65 66`; a non-printable byte → exact `.` per CV-01), TC-011 (byte-identical stored bytes before/after every render call).
- **Dependencies:** increment 1 (`MemoryChange.new_bytes`).
- **Risks:** Low — pure deterministic mapping. The only pinned-detail risk is the placeholder character; CV-01 fixed it to `.` (0x2E) and TC-010 asserts that exact character. ASCII positional alignment (one char per byte) must hold so the ASCII string lines up with the hex form.

### Increment 4 — Unified change-set container

- **LLRs:** LLR-004.1 (holds one `ChangeList` + one `MemoryChangeList` as distinct attributes; parameter half is a plain `ChangeList`, no `ResolutionResult`), LLR-004.2 (composes — does not subclass — `ChangeList`; `changelist.py` byte-unchanged), LLR-004.3 (independent mutation of each half), LLR-004.4 (per-half counts), LLR-004.5 (empty-state query).
- **TCs:** TC-012, TC-013, TC-026 (compose-not-subclass runtime corroboration); contributes to TC-027 (inspection — completed in increment 9).
- **Files (≤5):**
  1. `s19_app/tui/cdfx/changeset.py` — **new.** `UnifiedChangeSet` — `__init__` builds an empty `ChangeList` and `MemoryChangeList`; `parameters` / `memory` attributes; `counts() -> tuple[int,int]`; `is_empty() -> bool`.
  2. `s19_app/tui/cdfx/__init__.py` — **edit.** Re-export `UnifiedChangeSet`.
  3. `tests/conftest.py` — **edit.** Add the `unified_changeset_factory` generator (per §5.4) — composes a `change_list_factory` parameter half (inherits the three adversarial IEEE floats — Q-09 note) and a `memory_change_factory` memory half.
  4. `tests/test_unified_changeset.py` — **new.** TC-012, TC-013, TC-026.
- **Dependencies:** increments 1 (`MemoryChangeList`) + the batch-03 `ChangeList` (unchanged import). Independent of 2 and 3.
- **Risks:** Low. The only constraint risk is C-3 (compose, not subclass) — TC-026 asserts `isinstance` + non-subclass at runtime; the byte-unchanged half is the increment-9 TC-027 inspection. Keep `UnifiedChangeSet` a thin container — no validation, no I/O logic here (those are increments 5–7).

### Increment 5 — Unified change-set file write

- **LLRs:** LLR-005.1 (JSON document: format-id + version + parameter half + memory-field half), LLR-005.2 (each parameter entry encodes `parameter_name`, `array_index`, `value`, resolution-status), LLR-005.3 (memory-field half = JSON **array of objects**, `address` an integer-valued field never an object key, `new_bytes` an integer array — DD-10 / OQ-V1), LLR-005.4 (work-area containment: serialize-to-temp-then-`copy_into_workarea`, reparse-point rejection, dedup-suffix, containment rejection → `ValidationIssue`).
- **TCs:** TC-015, TC-016, TC-017, TC-018.
- **Files (≤5):**
  1. `s19_app/tui/cdfx/unified_io.py` — **new (write half).** `serialize_unified(changeset) -> bytes` (stdlib `json`) and `write_unified_to_workarea(changeset, base_dir, file_name) -> tuple[Path|None, list[ValidationIssue]]` — staged temp file + `copy_into_workarea`, mirroring `write_cdfx_to_workarea`'s pattern exactly (S-004 adaptation; no new write path — C-10). Define the `MF-*` code constants here (the rule-code module home).
  2. `s19_app/tui/cdfx/__init__.py` — **edit.** Re-export `write_unified_to_workarea` / `serialize_unified`.
  3. `tests/conftest.py` — **edit.** Add `make_unified_file` (a well-formed unified JSON file on `tmp_path`) — needed by increment 6's read TCs, introduced here since the writer produces it.
  4. `tests/test_unified_write.py` — **new.** TC-015, TC-016, TC-017, TC-018 (incl. the reparse-point arm via an injectable reparse-point probe — Q-11 / batch-03 CV-03 pattern — and the dedup-suffix arm).
- **Dependencies:** increment 4 (`UnifiedChangeSet`). Consumes `workspace.py` (`ensure_workarea`, `copy_into_workarea`, `WORKAREA_TEMP`, `WorkareaContainmentError`) read-only.
- **Risks:** `copy_into_workarea` is a file-*copy* primitive — the writer holds in-memory JSON, so it must serialize to `.s19tool/workarea/temp/` first then copy (S-004). The reparse-point arm needs a deterministic test mechanism (injectable probe) so a CI skip is never silent (Q-11). The memory-field on-disk shape is normatively pinned (DD-10) — `address` must be a JSON *number field*, not a dict key; getting this wrong is invisible until TC-025's round-trip in increment 9, so assert the array-of-objects shape directly in TC-017.

### Increment 6 — Unified change-set file read + `MF-*` rule set

- **LLRs:** LLR-006.1 (parse both halves), LLR-006.2 (`MF-JSON-PARSE` for malformed / deeply-nested JSON — catch `RecursionError` as a `RuntimeError`, not only `JSONDecodeError`; `MF-BAD-STRUCTURE` for well-formed-but-wrong-shape, no `KeyError`), LLR-006.3 (path resolution via `resolve_input_path`, `MF-PATH-UNRESOLVED`), LLR-006.4 (256 MB pre-parse size cap via the injectable size-probe seam, `MF-SIZE-CAP`), LLR-006.5 (decoded-structure ceiling: entry-count + single-`new_bytes`-run-length, `MF-ENTRY-LIMIT`, drop-offending-keep-rest), LLR-008.1 (per-entry structural rules: `MF-NO-ADDRESS` / `MF-EMPTY-BYTES` / `MF-BYTE-RANGE`), LLR-008.2 (`MF-VERSION-UNKNOWN` info-level, continue parsing).
- **TCs:** TC-014, TC-019, TC-020, TC-021, TC-022, TC-023, TC-024, TC-035, TC-037.
- **Files (≤5):**
  1. `s19_app/tui/cdfx/unified_io.py` — **edit (add read half).** `read_unified(path_text, base_dir, size_probe=...) -> tuple[UnifiedChangeSet, list[ValidationIssue]]` — path resolution → size cap → `json.load` (catching `JSONDecodeError` **and** `RecursionError`) → structural shape check → per-entry rules → decoded-structure ceiling. Pin and document the numeric ceiling constants and the `MF-*` code spellings (the §5.8 Phase-3 to-pin list).
  2. `s19_app/tui/cdfx/__init__.py` — **edit.** Re-export `read_unified`.
  3. `tests/conftest.py` — **edit.** Add `make_malformed_unified_file`, `make_rule_violation_unified_file` (parametrized, incl. the `MF-BAD-STRUCTURE` whole-document variants), `make_oversized_unified_file` (size-probe seam), `make_deeply_nested_unified_file`, `make_over_ceiling_unified_file`.
  4. `tests/test_unified_read.py` — **new.** TC-014, TC-019, TC-021, TC-022, TC-035, TC-037.
  5. `tests/test_unified_rules.py` — **new.** TC-020, TC-023, TC-024 (the `MF-*` per-entry / version / parse rules).
- **Dependencies:** increments 4 (`UnifiedChangeSet`) + 5 (`unified_io.py` write half, `make_unified_file`, `MF-*` constants). Consumes `workspace.resolve_input_path` + `DEFAULT_COPY_SIZE_CAP_BYTES` read-only.
- **Risks:** The `RecursionError` catch (S-002) is the highest-value subtlety — `RecursionError` is a `RuntimeError`, not a `JSONDecodeError`; an `except json.JSONDecodeError` alone lets it escape. The except clause must catch both. The decoded-structure ceiling (S-001 / LLR-006.5) must be enforced *during reconstruction*, not from the file size — the ceiling constants need to be pinned and documented. The `MF-BAD-STRUCTURE` shape check must precede any `doc["memory"]` indexing or a `KeyError` escapes (Q-07). This is a dense increment (9 TCs); the two test files keep each focused. If `unified_io.py` grows past the granularity trigger, split a `_mf_rules.py` helper — but that pushes the file count, so prefer keeping the rule helpers as private functions in `unified_io.py`.

### Increment 7 — Selective export coordinator

- **LLRs:** LLR-007.1 (CDFX file via the **unchanged** `write_cdfx_to_workarea`, fed a re-resolved `ResolutionResult`), LLR-007.2 (memory-field JSON file, array-of-objects shape, own write-path containment clause mirroring LLR-005.4), LLR-007.3 (two distinct files, never merged), LLR-007.4 (collect each half's issues into one result, tag origin on `ValidationIssue.artifact` — `param-half` / `memory-half`; no model change — C-5 / A-5), LLR-007.5 (export-time re-resolution via `resolve_against_a2l`; no-A2L → unresolved `ResolutionResult` + one `ValidationIssue`, no raise — DD-11).
- **TCs:** TC-028, TC-029, TC-030, TC-031, TC-036.
- **Files (≤5):**
  1. `s19_app/tui/cdfx/export.py` — **new.** `export_unified(changeset, base_dir, a2l_tags, ...) -> ExportResult` (or `tuple[Path|None, Path|None, list[ValidationIssue]]`): re-resolve the parameter half (`resolve_against_a2l`), call `write_cdfx_to_workarea` unchanged, write the memory-field JSON via a `write_memory_field_to_workarea` helper (reuses the increment-5 temp-then-copy pattern), tag and combine issues.
  2. `s19_app/tui/cdfx/unified_io.py` — **edit.** Add `write_memory_field_to_workarea` (memory-half-only JSON file — format-id + version + the array-of-objects memory entries) if not better placed in `export.py`; reuses the increment-5 serialize-to-temp helper.
  3. `s19_app/tui/cdfx/__init__.py` — **edit.** Re-export `export_unified`.
  4. `tests/conftest.py` — **edit.** Confirm `make_patch_a2l` (reused from batch-03) is importable in the batch-04 fixture set; add a memory-field-export helper fixture if needed.
  5. `tests/test_unified_export.py` — **new.** TC-028, TC-029, TC-030 (spy on `write_cdfx_to_workarea` + `writer.py` byte-unchanged), TC-031, TC-036 (spy on `resolve_against_a2l`; A2L-loaded and no-A2L arms).
- **Dependencies:** increments 4 (`UnifiedChangeSet`) + 5 (`unified_io` write half). Consumes the batch-03 `write_cdfx_to_workarea` + `resolve_against_a2l` **unchanged** (C-1).
- **Risks:** The A-1 blocker resolution lives here — the coordinator must re-resolve the bare `ChangeList` against the loaded A2L *before* the CDFX write (DD-11 / LLR-007.5), exactly mirroring `cdfx_service.save`. Getting this wrong reproduces the original `TypeError`-at-export defect. The per-half origin tag must use the existing `ValidationIssue.artifact` field (`param-half` / `memory-half`) — no new field, no model change (C-5 / A-5). TC-030 must verify `writer.py` is byte-unchanged (hash/diff check) — confirm no accidental edit crept in.

### Increment 8 — Patch Editor UI extension

- **LLRs:** LLR-009.1 (render the memory-change list as rows — address, hex, status — alongside the parameter-change rows, without removing them), LLR-009.2 (memory-change controls — address input, new-bytes input, add/edit/remove — wired through the service layer; `app.py` holds only UI-state wiring — C-7), LLR-009.3 (save / load / selective-export actions wired, surfacing `ValidationIssue` results through the existing status path).
- **TCs:** TC-032, TC-033, TC-034 (integration); finalizes the TC-027 inspection input (the `app.py`-clean clause).
- **Files (≤5):**
  1. `s19_app/tui/services/cdfx_service.py` — **edit.** Extend `CdfxService` with memory-change operations (`add_memory_change` / `edit_memory_change` / `remove_memory_change`), `memory_rows()`, and unified `save_unified` / `load_unified` / `export_selective` — wrapping `changeset.py`, `unified_io.py`, `export.py`. Holds a `UnifiedChangeSet` (or composes its existing `ChangeList` into one).
  2. `s19_app/tui/screens_directionb.py` — **edit.** Extend `PatchEditorPanel` — memory-change rows in the rendered table, the address + new-bytes inputs, add/edit/remove buttons, save/load/export-selective controls. Posts action messages; calls `CdfxService`.
  3. `s19_app/tui/app.py` — **edit.** UI-state wiring only — handle the new Patch Editor action messages by calling `CdfxService` and feeding results back to the panel (no JSON parse/serialize, no model logic — C-7 / LLR-009.2).
  4. `tests/test_tui_patch_editor.py` — **edit** (or new `tests/test_tui_memory_patch.py`). TC-032, TC-033, TC-034 — driven headlessly via `App.run_test()` / Textual `pilot`, the established `test_tui_directionb.py` / `test_tui_patch_editor.py` harness.
- **Dependencies:** increments 4–7 (the whole data + I/O + export stack). This is the integration seam.
- **Risks:** RK-5 (Patch Editor screen growth) — the batch-03 parameter-change rows/controls must survive intact; TC-032 explicitly asserts both kinds coexist. C-7 is easy to violate by accident — keep all model/JSON/export logic in the service; `app.py` only routes messages. `app.py` is ~5k lines already (`CLAUDE.md`) — add the minimum wiring, extend `CdfxService` for everything else. The 4-file count is tight; if `screens_directionb.py` + `cdfx_service.py` + `app.py` + the test file is not enough, the layout work may need a small split — flag at the increment boundary rather than silently exceeding the cap.

### Increment 9 — Round-trip + integration hardening

- **LLRs:** LLR-006.1 (round-trip corroboration); closes the TC-027 inspection checklist for LLR-004.2 + LLR-009.2.
- **TCs:** TC-025 (the round-trip — primary verdict for LLR-006.1, corroborating for HLR-005/HLR-006), TC-027 (the §5.6 inspection checklist). Re-confirms TC-032/033/034 if any drift.
- **Files (≤5):**
  1. `tests/test_unified_roundtrip.py` — **new.** TC-025 — build a `UnifiedChangeSet` via `unified_changeset_factory` (scalar + 1-D array + ASCII + the three adversarial IEEE floats; memory half inside + partial + outside + a multi-byte run), write → read, assert structural equality with **exact `==`** on parameter values and the exact ordered byte sequence on every memory entry; status fields excluded from the equality predicate (re-derived on read — Q-06), deterministic order preserved.
  2. `tests/test_cdfx_unchanged.py` — **new (or fold into `test_unified_export.py`).** TC-027 — the §5.6 inspection checklist as an executable test: `changelist.py` / `reader.py` / `writer.py` byte-unchanged (file-hash assertion), no JSON/model logic in `app.py` (a static grep-style assertion), `pyproject.toml` / `requirements.txt` unchanged.
  3. *(reserve)* `tests/conftest.py` — **edit** only if the round-trip needs a fixture variant not already present.
- **Dependencies:** all of increments 1–8.
- **Risks:** TC-025 is the strongest correctness test — any write/read defect from increments 5/6 surfaces here, possibly forcing a fix back in those modules. Schedule a buffer. The adversarial-float exact-`==` (no tolerance) only passes if the JSON path preserves full binary64 — stdlib `json` does, but a lossy intermediate string conversion would fail it; that is the intended sensitivity. TC-027's "byte-unchanged" assertion must be robust to line-ending / `__pycache__` noise — hash the source file content, not the directory.

---

## D. Cross-cutting notes

- **`MF-*` code spellings** — pinned in increment 5 (`unified_io.py` constants) and documented there before increment 6's tests assert on them: `MF-JSON-PARSE`, `MF-BAD-STRUCTURE`, `MF-NO-ADDRESS`, `MF-EMPTY-BYTES`, `MF-BYTE-RANGE`, `MF-VERSION-UNKNOWN`, `MF-SIZE-CAP`, `MF-ENTRY-LIMIT`, `MF-PATH-UNRESOLVED` (§5.4 / §5.8).
- **Numeric ceilings (LLR-006.5)** — the memory-field entry-count ceiling and the single-`new_bytes`-run-length ceiling are pinned as named constants in `unified_io.py` (increment 6) and read by `make_over_ceiling_unified_file`.
- **ASCII placeholder** — pinned to `.` (0x2E) in `memory_display.py` (increment 3); CV-01 aligns TC-010 to assert that exact character.
- **Collect-don't-abort** — every validator/reader function returns `(result, list[ValidationIssue])` and never raises on a data-quality fault; the only intentional raise is `MemoryChange.__post_init__`'s `ValueError` (LLR-002.5, construction-time). This split is the A-4 finding's two-opposite-semantics resolution.
- **No new dependency** (C-4) — every increment uses stdlib `json` only; `pyproject.toml` / `requirements.txt` stay unchanged (asserted by TC-027 in increment 9).
- **Docstrings** — every new public function carries the `PROJECT_RULES.md` section order (Summary → Args → Returns → Raises → Data Flow → Dependencies → Example) and type hints (C-6); the batch-03 `cdfx/` modules are the style baseline.
- **Suite-green gate** — each increment ends with `pytest -q` at 611 baseline + that increment's new cases, 0 failures; a runnable `s19tui`.
- **Security hand-off** — increments 5, 6 and 7 carry the write-path containment, the read-path resource bounds (size cap, decoded-structure ceiling, `RecursionError` catch) and the export write paths. Per the cross-functional handoff rule, request a `security-reviewer` pass over increments 5–7 before merge (the §5.5 hand-off surface).
- **QA hand-off** — after increment 8 ships the functional screen, propose the TC-032/033/034 manual test plan + acceptance criteria to `qa-reviewer`.
- **File-cap discipline** — increment 8 is the tightest (4 files, all edits to large existing modules). If the UI layout genuinely needs a 6th file, stop at the boundary and request approval rather than exceeding the cap.

---

## E. Dependency graph

```
1 (model) ──┬─► 2 (validate) ──┐
            ├─► 3 (display) ───┤
            └─► 4 (container) ─┴─► 5 (write) ──► 6 (read) ──┐
                                       └────────► 7 (export) ┤
                                                  2,3,5,6,7 ─► 8 (UI) ──► 9 (round-trip + inspection)
```

Increments 2 and 3 depend only on 1 and could run in parallel; 4 depends only on 1; the plan keeps them sequential for a single supervised arc. 5 needs 4; 6 needs 5; 7 needs 5; 8 needs 2–7; 9 needs all.
