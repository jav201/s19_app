# Functionality — s19_app — 2026-05-21-batch-04 (memory-value editing + unified change-set + selective export)

**Audience:** a technical stakeholder, future engineer, or QA reviewer who needs to understand what batch-04 added to `s19_app` — the raw-memory change kind, validation against the loaded image, hex/ASCII/decimal value display, the unified change-set container, the unified-file JSON read/write handler, selective export, and the Patch Editor extension — and what was deliberately left unbuilt.

**Purpose:** describe (a) what the batch is and why it adds a data layer beside the batch-03 `cdfx/` package, (b) the memory-change model, (c) validation against the loaded image's address ranges, (d) memory-change value display, (e) the `UnifiedChangeSet` container, (f) the unified-file JSON write/read handler and the `MF-*` rule set, (g) selective export, (h) the Patch Editor memory-change extension, and (i) what is explicitly deferred.

**Scope:** this is the **orientation document**. It is *not* the requirements specification ([`01-requirements.md`](../01-requirements.md)), *not* the per-test verdict register ([`04-validation.md`](../04-validation.md)), and *not* the traceability matrix ([`traceability-matrix.md`](traceability-matrix.md)). It lets a new reader navigate those artefacts. For the visual call-graph see [`diagrams/architecture.md`](diagrams/architecture.md).

---

## 1. What batch-04 is

`s19_app` (distribution name `s19tool`) is an offline desktop tool for parsing, validating and visualising automotive memory artefacts — S-record / Intel HEX firmware images, ASAM A2L description files, and MAC `TAG=hexaddr` symbol files. It ships two entry points: `s19tool` (Rich CLI) and `s19tui` (Textual TUI).

Batch `2026-05-21-batch-03` made the `s19tui` **Patch Editor** functional for **A2L parameter changes**: a parameter `ChangeList` model, parameter resolution against the loaded A2L, type-driven display, and ASAM CDFX (`.cdfx`) read/write. Batch `2026-05-21-batch-04` extends the Patch Editor so it can also edit **raw memory values** — direct `(memory address → new bytes)` changes against the loaded firmware image — not only A2L calibration parameters. It lets a calibration / firmware engineer:

1. **Build a memory-change list** — a structured set of intended raw-memory edits, each keyed by a memory **address** and holding a contiguous run of new byte values for that address.
2. **Validate each memory change** against the loaded firmware image's address ranges — learning whether the edit lands fully `inside`, `partial`-ly across, or fully `outside` the image's written ranges.
3. **See each memory value** in hex (primary), ASCII and decimal at once, without manual conversion.
4. **Hold both kinds in one container** — the `UnifiedChangeSet` composes the batch-03 parameter `ChangeList` AND the new `MemoryChangeList`, and **save / load both halves as one JSON file** — the working-document format for the whole patch set.
5. **Selectively export** the unified change-set — a CDFX `.cdfx` file for the parameter half (produced by the **unchanged** batch-03 CDFX writer) and a separate JSON file for the memory-field half — so each half reaches the tool that consumes it (vCDM for CDFX).

This batch **deliberately adds a data layer** beside the batch-03 `cdfx/` package — that expansion was approved and expected ([`01-requirements.md`](../01-requirements.md) §1.1, §2.1). It does **not** open a new architectural layer: the six new modules are a **peer addition inside `s19_app/tui/cdfx/`**, mirroring the batch-03 package layout, plus the `cdfx_service.py` orchestration extension.

The **engine remains frozen.** The Phase-4 `git diff main` over `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` is empty — zero bytes changed ([`04-validation.md`](../04-validation.md) §2). The batch-03 CDFX writer (`writer.py`) and resolver (`resolve.py`) are confirmed **byte-unchanged** by a SHA-256 pin; the batch-03 parameter `ChangeList` (`changelist.py`) and CDFX reader (`reader.py`) carry no batch-04 worktree edit. The batch-04 feature is purely additive new files; it **reuses** the loaded-image memory model (`LoadedFile.ranges`, read-only), the `ValidationIssue` / `ValidationSeverity` model, the severity-to-colour policy (`tui/color_policy.py`), the workspace helpers (`tui/workspace.py`), and the batch-03 CDFX writer + resolver — without re-implementing or modifying any of them.

**Like batch-03, no firmware image is modified.** The memory-change model is an edit *intent* — recorded but not applied (see §10).

### 1.1 What the batch delivered

| Output | Count | Where |
|--------|-------|-------|
| User stories | 5 (US-001..US-005) | [`01-requirements.md`](../01-requirements.md) §2.6 |
| High-level requirements | 9 (HLR-001..HLR-009) | [`01-requirements.md`](../01-requirements.md) §3 |
| Low-level requirements | 37 | [`01-requirements.md`](../01-requirements.md) §4 |
| Test cases | 37 (TC-001..TC-037 — no reserved/unallocated slot; TC-014 is the `MF-BAD-STRUCTURE` case) | [`01-requirements.md`](../01-requirements.md) §5.7; verdicts in [`04-validation.md`](../04-validation.md) §5 |
| Phase 3 increments | 9 | [`03-increments/increment-001.md`](../03-increments/increment-001.md) … [`increment-009.md`](../03-increments/increment-009.md) |
| New `s19_app/tui/cdfx/` modules | 6 (`memory.py`, `memory_validate.py`, `memory_display.py`, `changeset.py`, `unified_io.py`, `export.py`) | see §11 |
| New `R-*` rows in the living `REQUIREMENTS.md` | 5 (`R-MEM-001`..`R-MEM-005`) | repo-root [`REQUIREMENTS.md`](../../../REQUIREMENTS.md) |
| Phase 4 verdict | `pass-with-gaps` (0 blockers) | [`04-validation.md`](../04-validation.md) §9 |

---

## 2. The memory-change model

The memory-change list is the second change kind the unified change-set composes — the raw-memory peer of the batch-03 parameter `ChangeList` (HLR-001). It is a pure-data model — no Textual import, no I/O — implemented in `s19_app/tui/cdfx/memory.py`.

- **Entry structure (LLR-001.1).** Each entry (`MemoryChange`) holds at least: `address` (a non-negative integer memory **start** address), `new_bytes` (an ordered, non-empty run of integer byte values, each `0–255`, stored as an **immutable tuple** so the display layer cannot mutate it), and a validation-status field. The entry exposes its addressed byte range as the half-open span `(address, address + len(new_bytes))`.
- **One entry = one contiguous run (DD-3 / A-4).** A memory-change entry addresses **one contiguous byte range** — one start address plus a run of one or more new bytes. A non-contiguous set of edits is modelled as several entries.
- **Entry identity (LLR-001.3).** The `address` field is the entry identity. An `add` that targets an address that already has an entry **updates that entry in place** rather than creating a duplicate — mirroring the batch-03 `ChangeList` `(name, index)` identity rule. (Overlap *between* two distinct start addresses is a validation concern, not an identity concern — see §3.)
- **Operations (LLR-001.2).** `MemoryChangeList` provides `add`, `edit` (the `new_bytes` of an entry identified by its `address`) and `remove` (an entry by its `address`). An edit or remove of a missing address raises `KeyError`.
- **Deterministic ordering (LLR-001.4).** The model holds its entries in an address-keyed, **insertion-ordered** dict (the same choice as the batch-03 `ChangeList`), so repeated serialization of the same memory-change list produces byte-identical output. The `entries` accessor returns a defensive copy, not the backing store.
- **Malformed bytes rejected at construction (LLR-002.5).** A `new_bytes` run containing a **negative** byte, a byte **greater than 255**, or an **empty** run does not describe a recordable edit intent — `MemoryChange.__post_init__` rejects it with a hard `ValueError`. This is the **opposite** failure mode from the collect-don't-abort validator of §3: a malformed byte run is a construction error, an out-of-range *address* is a recordable intent that is flagged but kept.

---

## 3. Validation against the loaded image

Each memory-change entry names a raw address but carries no knowledge of whether the loaded firmware image actually covers that address. Validation (HLR-002, `s19_app/tui/cdfx/memory_validate.py`, `validate_memory_changes`) tests each entry against the **loaded image's address ranges** so the engineer is warned when an edit targets memory the image does not cover.

- **Reads the loaded-image ranges, never re-parses (constraint C-2, C-8).** The validator consumes the loaded image's contiguous `(start, end)` address ranges through the **`LoadedFile.ranges` snapshot** — read-only. It never re-parses a firmware file, never branches on `S19File` vs `IntelHexFile` (both loaders populate the same `LoadedFile.ranges` surface — risk RK-4), and never writes to the image.
- **Four validation states (LLR-002.1, LLR-002.3).** Each entry's addressed byte range `(address, address+len(new_bytes))` is tested against the loaded ranges and stamped with a `MemoryStatus`:
  - `inside` — the addressed range lies fully within one loaded range.
  - `partial` — the addressed range overlaps a loaded range but is not contained within a single one. An entry whose run **touches more than one loaded range** — for example a run that begins inside one range, crosses an inter-range gap, and ends inside another — receives the **single** status `partial` and is treated as **one** `partial` entry, not one status per touched range.
  - `outside` — the addressed range does not overlap any loaded range.
  - `unvalidated-no-image` — no firmware image is loaded; **every** entry is marked this way and no exception is raised (mirroring the batch-03 `unresolved-no-a2l` state — assumption A-2). A memory-change list is still buildable and usable before an image is loaded.
- **Collect-don't-abort (LLR-002.2).** A `partial` or `outside` entry produces **exactly one** warning-level `ValidationIssue` describing the entry's `address` and the mismatch — never an exception. A gap-spanning entry that touches several ranges still produces exactly one issue, so the test-case count stays deterministic. The out-of-range edit is **recorded with a warning, never dropped or rejected** — the engineer may still intend it, and applying it is deferred anyway (§10).
- **Inter-entry overlap check (LLR-002.4).** The validator appends one warning-level `ValidationIssue` for each memory-change entry whose addressed byte range overlaps the addressed byte range of **another** entry with a **distinct `address`** in the same list. Overlapping edits between two distinct start addresses are almost always a mistake (two entries writing the same byte); the conflict is **flagged — never merged** (which would invent a combined edit) and **never rejected** (the engineer may still intend both) — consistent with the batch-03 fail-loud, no-silent-fix culture (§6.2.1 OQ-8). Overlap is distinct from the identity collision of §2: two adds at the *same* address update in place; two distinct addresses with intersecting runs each get a warning.
- **No raw firmware bytes in issue messages (constraint C-9).** A memory-field `ValidationIssue` message references the entry's `address` and a byte-count summary (for example "12 bytes") — it **never embeds the raw `new_bytes` content verbatim**, so proprietary firmware bytes are kept out of the 5 MB rotating log (`.s19tool/logs/s19tui.log`).

Every finding is a `ValidationIssue` (`s19_app/validation/model.py`) reused as-is — its `artifact` field carries a string tag (`memory-half`) identifying the producing concern, and its `severity` round-trips through `color_policy.css_class_for_severity` to a valid `sev-*` CSS class (LLR-008.3). No new issue model was introduced.

---

## 4. Memory-change value display

A memory-change value is **entered and stored as raw bytes**; the display layer derives three companion renderings for the engineer to verify against (HLR-003, `s19_app/tui/cdfx/memory_display.py`, `format_memory_value`). Display is a UI concern derived from the stored bytes — it **never mutates** them (LLR-003.3); the stored `new_bytes` tuple is byte-identical before and after every rendering call.

`format_memory_value` returns a `MemoryValueRendering` carrying all three forms (LLR-003.1, LLR-003.2):

| Form | Rule |
|------|------|
| **Hex** (primary) | A space-separated sequence of **two-digit uppercase** hexadecimal byte tokens — `[0x01, 0xAB, 0xFF]` renders `01 AB FF`. Hex is the natural primary form for raw memory. |
| **ASCII** (companion) | Each byte in the printable ASCII range `0x20–0x7E` is shown as its character; **every other byte** is shown as the single fixed placeholder character `.` (the period, byte `0x2E` — the conventional hex-dump placeholder). `[0x41, 0x42]` renders `AB`. The placeholder keeps **one character per byte**, so the ASCII rendering stays positionally aligned with the hex rendering. |
| **Decimal** (companion) | A space-separated sequence of decimal byte values — `[0x41, 0x42]` renders `65 66`. |

ASCII lets the engineer recognise string content; decimal is the plain numeric companion. The placeholder is **pinned** to `.` (`0x2E`) so two implementations cannot disagree and both pass a test — `test_tc010_non_printable_byte_renders_as_the_exact_dot_placeholder` asserts that exact character (the Phase-2 CV-01 closure).

---

## 5. The unified change-set container

The `UnifiedChangeSet` (HLR-004, `s19_app/tui/cdfx/changeset.py`) is the in-app container that makes one save, one load and one screen possible for the whole patch set. It holds **both** change kinds without merging them.

- **Holds both halves (LLR-004.1).** A `UnifiedChangeSet` holds one batch-03 parameter `ChangeList` instance and one `MemoryChangeList` instance, exposed as **distinct attributes** for independent access. Keeping the two halves distinct — a parameter change and a memory change are different kinds, keyed differently — is what makes selective export and the unchanged-CDFX-writer reuse possible.
- **Composes, does not subclass (LLR-004.2, constraint C-3).** The container references the batch-03 `ChangeList` type **by composition** — it holds a `ChangeList` as a member. It does **not** subclass it, alter its behaviour, or modify `s19_app/tui/cdfx/changelist.py`, which is byte-unchanged this batch.
- **The parameter half is resolution-free (LLR-004.1, A-7).** The parameter half is a **plain `ChangeList`** — it carries no `ResolutionResult` and no resolution state. Resolution against the loaded A2L is **not** part of the container or the on-disk unified file; it is a transient computation performed only at selective-export time (§7). Keeping the container and the unified file resolution-free is what lets the unified file be saved and reloaded without an A2L present.
- **Independent mutation (LLR-004.3).** A mutation of the memory-field half leaves the parameter half unchanged, and vice versa.
- **Per-half counts and empty-state (LLR-004.4, LLR-004.5).** The container reports the parameter-half entry count and the memory-field-half entry count **separately**, and reports whether it is empty — where empty means both halves have zero entries.

---

## 6. The unified change-set file — JSON write and read

The unified change-set file is the **working-document format** for the whole patch set — one on-disk JSON file holding both halves (HLR-005 / HLR-006). It is read and written by `s19_app/tui/cdfx/unified_io.py` using the Python **standard library `json` module only** — no new runtime dependency (constraint C-4, design decision DD-1). Unlike the batch-03 XML path, `json` has no entity-expansion / DOCTYPE / external-entity attack surface, so the billion-laughs / `SYSTEM`-entity defences of batch-03 have no batch-04 equivalent.

### 6.1 Writing the unified file (HLR-005)

`serialize_unified` produces the JSON bytes; `write_unified_to_workarea` places the file.

- **JSON structure (LLR-005.1).** The document carries a **format-identifier** field (`UNIFIED_FORMAT_ID = "s19app-unified-changeset"`), a **version** field (`UNIFIED_FORMAT_VERSION = "1.0"`), a parameter half holding the parameter `ChangeList` entries, and a memory-field half holding the `MemoryChangeList` entries. The format-id + version header lets the reader recognise the file and tolerate future format revisions — the same self-describing discipline the CDFX `CATEGORY=CDF20` token gives the batch-03 format.
- **Parameter-half encoding (LLR-005.2).** Each parameter `ChangeListEntry` is encoded with at least its `parameter_name`, `array_index` (including the `None` scalar/string shape), `value` and resolution-status fields — the plain JSON shape of the batch-03 `ChangeListEntry`, distinct from the CDFX XML export format.
- **Memory-half encoding (LLR-005.3, DD-10).** The memory-field half is a JSON **array of objects** — one object per memory-change entry — each object carrying `address` as an **integer-valued field** (a JSON number) and `new_bytes` as a JSON array of integers. `address` is **never** encoded as a JSON object key: JSON object keys are always strings, so a key would force every reader to re-parse it and would open an undocumented hex-vs-decimal ambiguity between writer and reader. Encoding `address` as an integer field makes it survive natively through stdlib `json`. (The in-app `MemoryChangeList` still keys entries by `address` — that is the *in-memory* shape; DD-10 pins only the *on-disk* shape.)
- **Work-area containment (LLR-005.4, constraint C-10).** The writer **reuses the batch-03 `workspace.py` containment path unchanged** — it serializes the unified change-set to a transient file under `.s19tool/workarea/temp/` and then calls `copy_into_workarea` to place it at the target. The write path rejects a target that traverses a symbolic link or NTFS reparse point, dedup-suffixes a colliding file name, and surfaces a containment rejection as a `ValidationIssue` rather than an uncaught exception. The hardened containment primitive is reused exactly — containment and reparse-point checks are not re-inlined into a fresh write path. A staged-write `OSError` (a `PermissionError`, a full disk) is also caught and surfaced as a `ValidationIssue` (the increment-9 S57-02 closure — see §9).

### 6.2 Reading the unified file (HLR-006)

`read_unified` parses a unified-file path into a `UnifiedChangeSet` and collects every finding as a `ValidationIssue` **without aborting the load** — the project's collect-don't-abort culture, applied to every reader failure mode.

- **Parse both halves (LLR-006.1).** A well-formed unified file parses to a unified change-set holding a populated parameter `ChangeList` and a populated `MemoryChangeList`.
- **Path resolution (LLR-006.3).** A user-supplied path is resolved through `workspace.resolve_input_path` before the file is opened — reusing the shared helper. An unresolvable path surfaces as one error-level `ValidationIssue` (`MF-PATH-UNRESOLVED`) with no file opened. `resolve_input_path` performs path *resolution* only (cwd + repo-root walk + `exists()`); reading a unified file *through* a symbolic link is accepted as in-threat-model for a local single-user offline tool (assumption A-6) — the real read-path boundary is the size and decoded-structure bounds below.

### 6.3 The `MF-*` rule set (HLR-008)

The reader (and the memory-field writer) apply a **fixed, documented set of structural validation rules**, emitting one `ValidationIssue` with a **stable code** per rule violation — the same discipline the batch-03 `W-*` / `R-*` rule set established. The `MF-*` prefix keeps the two batches' codes from colliding. The full set, pinned as named constants in `unified_io.py`:

| Code | Meaning | Severity | LLR |
|------|---------|----------|-----|
| `MF-JSON-PARSE` | the file is not well-formed JSON — a truncated/garbage document, **or** a document nested deep enough to make the stdlib `json` parser raise `RecursionError` | error | LLR-006.2 |
| `MF-BAD-STRUCTURE` | the file is well-formed JSON but does not carry the expected parameter half and memory-field half (a bare `[]`, `42`, string, or an object with no recognised halves) | error | LLR-006.2 |
| `MF-NO-ADDRESS` | a memory-field entry has no `address` | error | LLR-008.1 |
| `MF-EMPTY-BYTES` | a memory-field entry has an empty `new_bytes` sequence | error | LLR-008.1 |
| `MF-BYTE-RANGE` | a memory-field entry has a byte value outside `0–255` | error | LLR-008.1 |
| `MF-VERSION-UNKNOWN` | the file declares a version token the reader does not recognise — the reader records it and **continues parsing** | info | LLR-008.2 |
| `MF-SIZE-CAP` | the file's on-disk byte size exceeds the 256 MB cap (`workspace.DEFAULT_COPY_SIZE_CAP_BYTES`) — rejected **before** `json.load`, the file never loaded into memory | error | LLR-006.4 |
| `MF-ENTRY-LIMIT` | a decoded-structure ceiling is breached — more memory-field entries than `MF_ENTRY_COUNT_CEILING` (100 000), or a single `new_bytes` run longer than `MF_RUN_LENGTH_CEILING` (1 048 576 bytes) | error | LLR-006.5 |
| `MF-PATH-UNRESOLVED` | a user-supplied input path could not be resolved | error | LLR-006.3 |
| `MF-WRITE-CONTAINMENT` | a write-path containment / reparse-point rejection — also reused (increment-9 S57-02) for a staged-write `OSError` (see §9, Gap 4) | error | LLR-005.4, LLR-007.2 |

Two read-path resource bounds are load-bearing and deserve emphasis:

- **`MF-SIZE-CAP` — the on-disk size bound (LLR-006.4).** Before parsing, the reader probes the file's on-disk byte size; an over-256 MB file is rejected with one `MF-SIZE-CAP` issue and an empty change-set, never loaded into memory. The 256 MB cap is the **shared `DEFAULT_COPY_SIZE_CAP_BYTES`** constant the batch-03 ingest path uses, so one consistent size limit governs every file the app reads.
- **`MF-ENTRY-LIMIT` — the decoded-structure ceiling (LLR-006.5).** The on-disk size cap bounds the *file*, not the *decoded structure*. A well-formed sub-256-MB file can declare a `new_bytes` array of hundreds of millions of integers, or millions of memory-field entries — JSON integers and array overhead expand several-fold once parsed into Python objects, reaching multiple GB in memory from a sub-cap file. The reader therefore enforces an **entry-count ceiling** and a **single-run-length ceiling** *during reconstruction*; on a breach it emits one `MF-ENTRY-LIMIT` issue, **drops the offending element**, **keeps the rest**, and does not raise — collect-don't-abort applied to a resource-exhaustion vector.

The reader's exception handling catches **`RecursionError`** explicitly — `RecursionError` is a subclass of `RuntimeError`, **not** of `json.JSONDecodeError`, so an `except json.JSONDecodeError` clause alone would let a deeply-nested document escape and crash the load. A `MF-BAD-STRUCTURE` shape check runs **before** any indexing of the expected halves, so a wrong-shape document never raises an uncaught `KeyError`.

---

## 7. Selective export — CDFX + memory-field JSON

Each half of the unified change-set has a different consumer — vCDM consumes the CDFX parameter file, a memory-oriented tool or the engineer consumes the memory-field JSON — so selective export must **split, not merge** (HLR-007, `s19_app/tui/cdfx/export.py`, `export_unified`). A selective export produces **exactly two distinct files** (LLR-007.3), each placed inside the work area through the `workspace.py` containment path, never merged into one.

- **The CDFX parameter file, via the unchanged batch-03 writer (LLR-007.1, constraint C-1).** The parameter half is exported as a `.cdfx` file produced by invoking the **unchanged** batch-03 CDFX write path (`write_cdfx_to_workarea`). Batch-04 does not re-implement, fork, or modify CDFX serialization — `cdfx/writer.py` is byte-unchanged (SHA-256-pinned).
- **Export-time re-resolution of the parameter half (LLR-007.5, DD-11).** The batch-03 CDFX writer requires a mandatory typed `ResolutionResult`; the unified change-set carries the parameter half as a plain `ChangeList` with **no** `ResolutionResult` attached (the container and the unified file are resolution-free — §5). So immediately before the CDFX write, the export coordinator **re-resolves** the parameter `ChangeList` against the **currently loaded A2L** by reusing the batch-03 `resolve_against_a2l` path — the same path `cdfx_service` uses before a CDFX write — and feeds the writer the freshly-computed `ResolutionResult`. The writer is invoked literally unchanged; it is simply supplied a transient, export-time argument. **With no A2L loaded**, the export still proceeds: it produces an unresolved `ResolutionResult`, collects **one** `ValidationIssue`, and does not raise — mirroring the batch-03 `unresolved-no-a2l` collect-don't-abort pattern. Re-resolution is a transient export-time computation; it is never persisted to the unified file. (This re-resolution path is the fix that closed the A-1 blocker: feeding the batch-03 writer a plain `ChangeList` would have reproduced a `TypeError`-at-export defect.)
- **The memory-field JSON file (LLR-007.2).** The memory-field half is exported as a separate JSON file carrying a format-identifier field, a version field and the memory-change entries in the **same array-of-objects shape** as the unified file's memory half (DD-10). The memory-field file write resolves under `.s19tool/workarea/` through the same serialize-to-temp-then-`copy_into_workarea` containment path as the unified-file write — same reparse-point rejection, same dedup-suffix, same `ValidationIssue`-not-exception guarantee (constraint C-10).
- **Cross-half issue collection (LLR-007.4).** The coordinator collects the `ValidationIssue` results of the CDFX write and of the memory-field write into **one combined result** and tags each issue's origin on its existing `ValidationIssue.artifact` field (`param-half` / `memory-half`) — no new field, no model change (constraint C-5). The two halves export **independently**: a problem in the parameter half (for example an unresolved entry the CDFX writer excludes) does not block the memory-field export, and vice versa.

---

## 8. The Patch Editor memory-change extension

The Patch Editor rail screen (`PatchEditorPanel` in `s19_app/tui/screens_directionb.py`) is **extended** so the engineer can manage memory-field changes alongside the parameter changes — without removing or regressing the batch-03 parameter-change controls (HLR-009, risk RK-5).

- **Renders the memory-change list (LLR-009.1).** The screen renders the current memory-change list as a **row per entry** — memory address, hex rendering of the new bytes, and the entry's validation status — presented **alongside** the existing batch-03 parameter-change rows, which remain visible and functional.
- **Memory-change controls wired through the service (LLR-009.2, constraint C-7).** The screen wires its memory-change controls — an address input, a new-bytes input, and add / edit / remove actions — to the memory-change model **through the service layer**. `app.py` holds **only** the UI-state wiring: `on_patch_editor_panel_action_requested` routes `add_memory` / `edit_memory` / `remove_memory` / `save_unified` / `load_unified` / `export` through `self._cdfx_service`. There is **no** JSON parse/serialize call and **no** memory-change / unified-change-set / export model logic in `app.py` (verified by inspection, TC-027). A bad memory address is reported, not raised.
- **Save / load / selective-export actions (LLR-009.3).** The screen provides actions to **save** the unified change-set file, **load** a unified change-set file, and trigger the **selective export** — each invoking the corresponding `CdfxService` operation and surfacing its `ValidationIssue` results through the existing status path. A save writes JSON under `.s19tool/workarea/`; a save-then-load round-trips both halves; a malformed unified file surfaces issues **without crashing the screen**; the export action produces both the `.cdfx` and the memory-field JSON file.

The service seam — `CdfxService` in `s19_app/tui/services/cdfx_service.py` — is **extended**, not replaced: it gains memory-change operations (`add_memory_change` / `edit_memory_change` / `remove_memory_change`), `memory_rows()`, and the unified `save_unified` / `load_unified` / `export_selective` operations, holding a `UnifiedChangeSet`. It keeps its existing batch-03 parameter-change operations intact.

---

## 9. Security and resource-bound posture

The unified change-set file and the memory-field JSON file are **parsed from outside the app** — the read path (§6.2) is an external-input surface. The batch-04 read/write surface was reviewed by the Phase-2 security-reviewer and carried a combined `security-reviewer` pass over increments 5–7; increment 9 closed one further finding.

- **Read-path resource bounds.** The 256 MB on-disk size cap (`MF-SIZE-CAP`), the decoded-structure entry-count and run-length ceilings (`MF-ENTRY-LIMIT`), and the explicit `RecursionError` catch on deeply-nested JSON (`MF-JSON-PARSE`) together close the resource-exhaustion vectors a JSON reader faces — see §6.3. The security-reviewer findings S-001 (decoded-structure ceiling), S-002 (`RecursionError`) and S-003 (memory-field write-path clause) were folded into normative LLRs.
- **Write-path containment.** Every file batch-04 writes — the unified file and the memory-field export file — goes through the **unchanged** `workspace.py` containment path (serialize-to-temp-then-`copy_into_workarea`): work-area containment, reparse-point rejection, dedup-suffix, `ValidationIssue`-not-exception (constraint C-10).
- **Increment-9 S57-02 closure.** The increment-9 fix added an `except OSError` arm to `write_unified_to_workarea` and `write_memory_field_to_workarea` so a fault from the staged-temp write (a `PermissionError`, a full disk) surfaces as one `ValidationIssue` rather than escaping the collect-don't-abort contract. The fix **reuses** the existing `MF-WRITE-CONTAINMENT` code for that issue — which is slightly broad (an I/O fault is not a containment-traversal fault); the `OSError` type/detail is passed into the message so the fault stays diagnosable. A dedicated `MF-WRITE-IO` code was considered and rejected as scope creep; it remains an optional one-line follow-up (Gap 4, [`04-validation.md`](../04-validation.md) §8). The issue *behaviour* — one issue, no raise, correct per-artifact tag — is correct and tested.
- **No raw firmware bytes in logs (constraint C-9).** A `ValidationIssue` produced for a memory-field finding references the entry's `address` and a byte-count summary — it never embeds the raw `new_bytes` content verbatim, keeping proprietary firmware bytes out of the rotating log.
- **Synthetic fixtures only (constraint C-9).** Every firmware-image / `.cdfx` / unified-file / memory-field-file / change-list fixture is synthetic — generated programmatically in `tests/conftest.py`. No client artifact appears in `tests/`.

---

## 10. What is deferred

The batch was scoped strictly — build the memory-change kind, validate it, display it, hold both kinds in one container, read/write the unified file, and split the selective export. The following are **explicitly out of scope** ([`01-requirements.md`](../01-requirements.md) §1.2, design decision DD-9) and are the subject of follow-up batches:

- **Apply-to-image.** Applying the memory changes to the firmware image / memory map. The memory-change model is a recorded *intent* only — `S19File.set_bytes_at` / `set_string_at` are **not** invoked this batch. A memory change targeting an address outside the loaded ranges is *flagged* (`outside` / `partial`) but the edit is still recorded; it is **not** applied and **no** range is created.
- **Modified-image export.** Exporting a modified S19 / Intel HEX firmware file.
- **Undo / redo.** No history of edits in either change kind.
- **Creating new memory ranges.** Editing memory regions not covered by the loaded image.
- **Any change to the batch-03 CDFX format**, the CDFX writer/reader, or the parameter `ChangeList` semantics. The CDFX writer and resolver are reused **byte-unchanged**.
- **vCDM round-trip verification.** No live vCDM installation or sample `.cdfx` is available — vCDM compatibility is asserted from Vector documentation, not verified against a live instance. Since batch-04 reuses the byte-unchanged batch-03 CDFX writer, this is exactly the batch-03 position — an accepted residual risk (RK-2 / Gap 1).

---

## 11. New modules and how to verify

| Module | Role | Built in |
|--------|------|----------|
| `s19_app/tui/cdfx/memory.py` | The memory-change model — `MemoryStatus` / `MemoryChange` / `MemoryChangeList` | increment 1 |
| `s19_app/tui/cdfx/memory_validate.py` | `validate_memory_changes` — range validation against `LoadedFile.ranges`, inter-entry overlap check | increment 2 |
| `s19_app/tui/cdfx/memory_display.py` | `format_memory_value` — hex / ASCII / decimal `MemoryValueRendering` | increment 3 |
| `s19_app/tui/cdfx/changeset.py` | `UnifiedChangeSet` — composes the parameter `ChangeList` + the `MemoryChangeList` | increment 4 |
| `s19_app/tui/cdfx/unified_io.py` | `serialize_unified` / `write_unified_to_workarea` / `read_unified` — the unified-file JSON handler + the `MF-*` rule set | increments 5 (write), 6 (read) |
| `s19_app/tui/cdfx/export.py` | `export_unified` — the selective-export coordinator | increment 7 |
| `s19_app/tui/cdfx/__init__.py` | Narrow public import surface — re-exports each new public symbol (edit) | increments 1–7 |
| `s19_app/tui/services/cdfx_service.py` | `CdfxService` extended with memory-change + unified-file/export operations (edit) | increment 8 |
| `s19_app/tui/screens_directionb.py` | `PatchEditorPanel` extended with memory-change rows/controls + save/load/export actions (edit) | increment 8 |
| `s19_app/tui/app.py` | UI-state wiring only — the Patch Editor memory-change action handler (edit) | increment 8 |

The six new modules live inside the existing `s19_app/tui/cdfx/` package — a **peer addition** beside the batch-03 CDFX modules, consistent with the `parsers → engine → tui` architecture and the `CLAUDE.md` rule that new feature logic extends a service rather than `app.py`. The `cdfx/` directory name is now slightly broader than "CDFX"; the package docstring records that it also holds the memory-field / unified-change-set concern, and the directory name stays (renaming would touch every importer).

**To run the suite and read verdicts:**

```bash
pytest -q                              # full suite — 762 passed / 0 failed / 3 xfailed / 2 skipped, 27 snapshots
pytest tests/test_memory_changelist.py # the memory-change model
pytest tests/test_memory_validate.py   # validation against the loaded image
pytest tests/test_memory_display.py    # hex / ASCII / decimal display
pytest tests/test_unified_changeset.py # the UnifiedChangeSet container
pytest tests/test_unified_write.py     # unified-file JSON write
pytest tests/test_unified_read.py      # unified-file JSON read
pytest tests/test_unified_rules.py     # the MF-* rule set
pytest tests/test_unified_roundtrip.py # write -> read round-trip (TC-025)
pytest tests/test_unified_export.py    # selective export
pytest tests/test_tui_memory_patch.py  # the extended Patch Editor screen
pytest tests/test_cdfx_unchanged.py    # batch-03 CDFX writer/resolver byte-unchanged (TC-027/TC-030)
```

The memory / unified / export subset is 11 test files, **151 passed / 0 failed**. The pre-existing 2 skips and 3 xfails are inherited batch-01/02/03 baseline cases — they are **not** batch-04 cases.

**To launch the TUI with the Patch Editor:**

```bash
s19tui --load examples/case_00_public/prg.s19
```

Open the Patch Editor (rail item 6), add/edit/remove memory-field changes, observe the hex/ASCII/decimal rendering and the `inside`/`partial`/`outside` status, save and load a unified `.json`, then trigger the selective export.

---

## 12. Where to go next

- The full requirement → test trace: [`traceability-matrix.md`](traceability-matrix.md).
- The per-test and per-requirement verdicts: [`04-validation.md`](../04-validation.md).
- The visual architecture and data-flow diagrams: [`diagrams/architecture.md`](diagrams/architecture.md).
- The batch-03 functional Patch Editor + CDFX feature this batch extends: [`.dev-flow/2026-05-21-batch-03/06-docs/functionality.md`](../../2026-05-21-batch-03/06-docs/functionality.md).
- The four `-with-gaps` items (vCDM interop, `ruff` in CI, manual Patch Editor pass, the `MF-WRITE-CONTAINMENT`-for-`OSError` note): [`04-validation.md`](../04-validation.md) §8 and [`traceability-matrix.md`](traceability-matrix.md) §3.
- The living requirements with the 5 new `R-MEM-*` rows: repo-root [`REQUIREMENTS.md`](../../../REQUIREMENTS.md).
