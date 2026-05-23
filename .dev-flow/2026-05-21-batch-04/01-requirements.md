# Requirements Document — s19_app — Batch 2026-05-21-batch-04

> **Strict normative convention — IEEE 830 + EARS**
> - `shall` = normative, binding, verifiable requirement. **Only** inside HLR / LLR statements.
> - `should` = informative / explanatory text, **NOT binding**. **Only** outside HLR / LLR statements (rationale, description, context).
> - Any use of `should` inside an HLR / LLR statement is a **writing error** and will be flagged as a blocker in phase 2.
> - `may` = optional. `will` = future declaration or fact about an external actor.

---

## 1. Introduction

### 1.1 Purpose

This document specifies the requirements for **batch-04** of `s19_app`:
extending the **Patch Editor** so it can also edit **raw memory values** —
direct `(memory address → new value/bytes)` changes against the loaded
firmware image — not only A2L calibration parameters.

Batch-03 made the Patch Editor functional for **A2L parameter changes**: a
`ChangeList` model, parameter resolution against the loaded A2L, type-driven
display, and CDFX (`.cdfx`) read/write. Batch-04 adds a **second, parallel
change kind** — the **memory-field change** — keyed by memory address rather
than by parameter name, and unifies both kinds behind one in-app container and
one on-disk file. Selective export then splits the unified set back into the
two artifacts each consumer expects: a CDFX file for the parameter half
(produced by the **unchanged** batch-03 CDFX writer) and a separate JSON file
for the memory-field half.

This batch **deliberately adds a data layer** beside the batch-03 `cdfx/`
package: a memory-change model, a unified change-set container, a JSON
file handler, and a selective-export coordinator. That expansion is approved
and expected. Like batch-03, **no firmware image is modified** — the
memory-change model is an edit *intent*, recorded but not applied.

### 1.2 Scope

**In scope:**
- A **memory-change model** — entries keyed by a memory **address**, each
  holding a contiguous run of **new bytes** for that address; the value is
  displayed in the best form (hex / ASCII / decimal — §6.2 DD-2).
- **Validation** of each memory-change entry against the **loaded firmware
  image's address ranges** (consuming `S19File` / `LoadedFile` read-only),
  collecting issues via the existing `ValidationIssue` collect-don't-abort
  pattern — never aborting.
- A **unified change-set** — one in-app container holding BOTH the batch-03
  A2L parameter `ChangeList` AND the new memory-field change list.
- **Unified change-set file** — read and write of one on-disk file
  (stdlib `json`, §6.2 DD-1) holding both halves, validated on read with
  collect-don't-abort.
- **Selective export** from the unified change-set: a **CDFX** file for the
  parameter half (REUSING the batch-03 CDFX writer **unchanged**) and a
  **separate JSON file** for the memory-field half.
- The **Patch Editor UI extension** — managing memory-field changes alongside
  parameter changes in the same screen.

**Out of scope (explicitly deferred — §6.2 DD-9):**
- **Applying** the memory changes to the firmware image / memory map. The
  memory-change model is a recorded *intent* only; `S19File.set_bytes_at` /
  `set_string_at` are **not** invoked this batch.
- Exporting a modified S19 / Intel HEX firmware file.
- Undo / redo of edits in either change kind.
- Editing memory regions not covered by the loaded image (creating new
  ranges) — a memory change targeting an address outside the loaded ranges is
  *flagged* (§4 LLR-002.x) but the edit is still recorded; it is **not**
  applied and no range is created.
- Any change to the batch-03 CDFX format, the CDFX writer/reader, or the
  parameter `ChangeList` semantics.

If a requirement below drifts toward applying changes to the image,
exporting modified firmware, or undo/redo, it is scoped out here and the
deferral is recorded in §6.2.

### 1.3 Definitions, acronyms, abbreviations

| Term | Definition |
|------|------------|
| A2L | ASAM MCD-2 MC file describing ECU parameters. Parsed by `s19_app/tui/a2l.py`. |
| Parameter change | A batch-03 change-list entry — an A2L `(parameter_name, array_index, value)` calibration change. |
| `ChangeList` | The batch-03 parameter change-list model (`s19_app/tui/cdfx/changelist.py`). Unchanged this batch. |
| Memory-field change / memory change | A batch-04 change keyed by a memory **address**, holding a contiguous run of new bytes for that address. |
| `MemoryChange` | The batch-04 memory-change entry record (this batch). |
| `MemoryChangeList` | The batch-04 ordered, address-keyed collection of `MemoryChange` entries (this batch). |
| Unified change-set | The batch-04 in-app container holding BOTH a `ChangeList` (parameter half) and a `MemoryChangeList` (memory-field half). |
| Unified change-set file | The batch-04 on-disk JSON file holding both halves of the unified change-set. |
| Memory-field export file | The separate JSON file produced by selective export for the memory-field half only. |
| CDFX | ASAM CDF 2.0 calibration-data XML file (`.cdfx`); the batch-03 export format for the parameter half. |
| Loaded image | The firmware image currently loaded in the app — an `S19File` / `IntelHexFile`, surfaced to the TUI as a `LoadedFile` snapshot. |
| Address range | A contiguous `(start, end)` half-open memory range of the loaded image (`LoadedFile.ranges`, `S19File.get_memory_ranges`). |
| `ValidationIssue` | The project's structured finding record (`s19_app/validation/model.py`). |
| `LoadedFile` | The TUI snapshot of a loaded image (`s19_app/tui/models.py`) — exposes `mem_map`, `ranges`, `range_validity`. |
| Patch Editor | The Direction B rail screen this batch extends. |
| Selective export | Splitting the unified change-set into one CDFX file (parameter half) plus one JSON file (memory-field half). |

### 1.4 References

- `.dev-flow/2026-05-21-batch-03/01-requirements.md` — the batch-03 parameter
  change-list + CDFX read/write contract (7 US / 8 HLR / 44 LLR) this batch
  builds on without modifying.
- `.dev-flow/2026-05-21-batch-03/03-increments/increment-plan.md` — the
  batch-03 increment plan; the `cdfx/` package layout and `cdfx_service`
  pattern carried forward here.
- `CLAUDE.md`, `PROJECT_RULES.md`, `REQUIREMENTS.md` — project architecture,
  docstring conventions, and `R-*` requirement traceability.
- Code consumed read-only: `s19_app/core.py` (`S19File`), `s19_app/hexfile.py`
  (`IntelHexFile`), `s19_app/tui/hexview.py`, `s19_app/tui/models.py`
  (`LoadedFile`).
- Code reused / extended: `s19_app/tui/cdfx/` (the whole package),
  `s19_app/tui/services/cdfx_service.py`, the Patch Editor in
  `s19_app/tui/screens_directionb.py`.
- Requirements template — `~/.claude/templates/dev-flow/req-template-en.md`.

### 1.5 Document overview

Section 2 gives the overall description, constraints, assumptions and source
user stories. Section 3 lists high-level requirements (HLR), each tracing to a
user story. Section 4 decomposes each HLR into low-level requirements (LLR).
Section 5 is the placeholder for the qa-reviewer validation strategy. Section 6
holds appendices — extended glossary, design decisions (including the
"Decisions taken in the owner's absence" subsection §6.2.1), and open risks.

This document specifies **5 user stories (US)**, **9 high-level requirements
(HLR)** and **37 low-level requirements (LLR)**. The LLR total by HLR group is:
4 (LLR-001.x) + 5 (LLR-002.x) + 3 (LLR-003.x) + 5 (LLR-004.x) +
4 (LLR-005.x) + 5 (LLR-006.x) + 5 (LLR-007.x) + 3 (LLR-008.x) +
3 (LLR-009.x) = **37**.

Section 5 (the qa-reviewer validation strategy) catalogues **37 active test
cases over 37 IDs (TC-001…TC-037); there is no reserved/unallocated slot —
TC-014 is allocated to the `MF-BAD-STRUCTURE` case** — this exact wording is
used wherever the catalogue size is stated.

---

## 2. Overall description

### 2.1 Product perspective

`s19_app` is a Python TUI/CLI for inspecting S19/Intel-HEX firmware images
cross-referenced with A2L and MAC artifacts. Its architecture has three layers:
**parsers → range/validation engine → TUI services + view code** (`CLAUDE.md`).

Batch-03 added a fourth concern beside the parsers: the `s19_app/tui/cdfx/`
package (the parameter `ChangeList`, resolver, display, CDFX writer/reader) and
the `cdfx_service` orchestration layer. Batch-04 **extends that same package**
with a memory-change model and a unified change-set, and adds a JSON file
handler and a selective-export coordinator. It does **not** open a new
architectural layer — it is a peer addition inside `s19_app/tui/cdfx/`.

The batch **consumes, read-only**: the loaded-image memory model
(`S19File.get_memory_map` / `get_memory_ranges`, `LoadedFile.mem_map` /
`ranges` / `range_validity`), the `ValidationIssue` / `ValidationSeverity`
model, the `color_policy` severity policy, and the `workspace.py` path helpers.
It **reuses, unchanged**: the batch-03 CDFX writer (`write_cdfx` /
`write_cdfx_to_workarea`) and the parameter `ChangeList` model.

### 2.2 Product functions

- F1 — Build a memory-change list: add, edit and remove entries keyed by a
  memory address, each holding a contiguous run of new bytes.
- F2 — Validate each memory-change entry against the loaded image's address
  ranges; collect issues without aborting.
- F3 — Display each memory-change value in the best form — hex (primary),
  with ASCII and decimal companion views.
- F4 — Hold both the parameter `ChangeList` and the `MemoryChangeList` in one
  unified change-set container.
- F5 — Write the unified change-set to one JSON file and read it back,
  validating on read with collect-don't-abort.
- F6 — Selective export: produce a CDFX file (parameter half, via the
  batch-03 writer) and a separate JSON file (memory-field half).
- F7 — Manage memory-field changes in the Patch Editor screen alongside the
  parameter changes.

### 2.3 User characteristics

The primary user is a **calibration / firmware engineer**: an
automotive/embedded professional fluent in both A2L calibration parameters and
raw memory layout (addresses, byte ranges, hex/ASCII representation). They run
`s19_app` to inspect a firmware image, and need to capture two distinct kinds
of intended change — high-level A2L parameter edits and low-level raw-memory
edits — in one place, exchange them as files, and hand the parameter half to
vCDM as a `.cdfx`. They are comfortable with a keyboard-driven TUI and expect,
per the project's culture, that malformed inputs (a bad address, an out-of-range
edit, a corrupt file) are reported as issues rather than crashing the tool.

### 2.4 Constraints

| ID | Constraint |
|----|------------|
| C-1 | The batch-03 `cdfx/` package CDFX writer (`write_cdfx`, `write_cdfx_to_workarea`, `validate_w_rules`) **shall be reused unchanged** for the parameter-half export; this batch **shall not** re-implement, fork, or modify CDFX serialization. |
| C-2 | The engine and parsers consumed by this batch — `s19_app/core.py`, `s19_app/hexfile.py`, `s19_app/validation/`, `s19_app/tui/a2l.py`, `s19_app/tui/mac.py` — **shall be consumed read-only**; this batch **shall not** modify any of them. The loaded-image memory model is an input, never a write target (the apply-to-image deferral, §6.2 DD-9). |
| C-3 | The batch-03 parameter `ChangeList` model (`s19_app/tui/cdfx/changelist.py`) and the batch-03 CDFX reader (`reader.py`) **shall not** be modified; the unified change-set composes the existing `ChangeList`, it does not subclass or alter it. |
| C-4 | All file read/write this batch — the unified change-set file and the memory-field export file — **shall use the Python standard library `json` module only**; no new runtime dependency **shall** be introduced (`rich`, `textual`, stdlib only). |
| C-5 | Every validation finding this batch produces **shall** be a `ValidationIssue` (`validation/model.py`) and **shall** follow the collect-don't-abort contract; its `severity` **shall** round-trip through `color_policy.css_class_for_severity`. No new issue model **shall** be introduced. |
| C-6 | New/changed code **shall follow `PROJECT_RULES.md`**: docstring section order (Summary→Args→Returns→Raises→Data Flow→Dependencies→Example), mandatory type hints, function granularity (~40-60 line split trigger). |
| C-7 | New parsing/serialization logic **shall live in a service-style module** (the `s19_app/tui/cdfx/` package or `tui/services/`), not inside `app.py`; `app.py` holds only UI-state wiring (`CLAUDE.md` TUI-layer rule, batch-03 LLR-007.5). |
| C-8 | The memory-change model and the unified change-set **shall not** modify, write, or apply changes to the firmware S19/HEX image; they are independent recorded-intent artifacts (the apply-to-image deferral, §6.2 DD-9). |
| C-9 | Test fixtures involving firmware images, `.cdfx`, the unified file or the memory-field file **shall use synthetic data only**, never client artifacts (consistent with the batch-03 `R-TUI-034` rule). Additionally, a `ValidationIssue` message produced for a memory-field finding **shall** reference the entry's `address` and a count or summary of the byte run, and **shall not** embed the raw `new_bytes` content verbatim — so proprietary firmware bytes are kept out of the 5 MB rotating log (`.s19tool/logs/s19tui.log`). |
| C-10 | A file written by this batch **shall be placed through the existing `workspace.py` work-area containment path** (the batch-03 `write_cdfx_to_workarea` / `copy_into_workarea` pattern); no new write path **shall** be introduced. A user-supplied input path **shall** be resolved through `workspace.resolve_input_path`. |

### 2.5 Assumptions and dependencies

| ID | Assumption — if false, the batch is invalidated or rescoped |
|----|-------------------------------------------------------------|
| A-1 | The batch-03 `cdfx/` package is present and green at the batch-04 start — `ChangeList`, `write_cdfx`, `write_cdfx_to_workarea`, `read_cdfx`, `CdfxService` exist with the signatures read for this document. If the batch-03 deliverable is not merged, batch-04 cannot reuse it. |
| A-2 | A memory-change entry is validated against an image that is **already loaded** in the app; building a memory change with no loaded image yields entries in an `unvalidated-no-image` state (a warning state), not a hard error — mirroring the batch-03 `unresolved-no-a2l` pattern (A2L-2). |
| A-3 | The loaded image exposes its written address ranges as a list of contiguous half-open `(start, end)` tuples and its written bytes as an address→byte map. `S19File.get_memory_ranges` / `get_memory_map` and `LoadedFile.ranges` / `mem_map` provide exactly this; the memory-change validator reads them and never re-parses the firmware file. |
| A-4 | A memory-change entry addresses a **contiguous byte range** — one start address plus a run of one-or-more new byte values. A non-contiguous set of edits is modelled as several entries. (Decision §6.2.1 OQ-1.) |
| A-5 | The memory-change value is **entered and stored as raw bytes**; hex is the primary display form, with ASCII and decimal as derived companion views (Decision §6.2.1 OQ-2). The stored bytes are the source of truth; the display forms never mutate them. |
| A-6 | The unified change-set file and the memory-field export file are **work-area-contained artifacts** written under `.s19tool/workarea/` through the existing `workspace.py` containment guards. The *write* side is the security boundary: containment, reparse-point rejection and collision handling are enforced on write (LLR-005.4, LLR-007.2). On the *read* side, a user-supplied input path is resolved through `workspace.resolve_input_path` — which performs **path resolution only** (cwd + repo-root walk + `exists()` check); it does **not** reject symbolic links or NTFS reparse points. Reading a unified file *through* a symbolic link is therefore **accepted as in-threat-model** for a local single-user offline tool: it is not an escalation, and the real read-path boundary is the size and decoded-structure bounds (LLR-006.4, LLR-006.5, LLR-006.2). |
| A-7 | The unified change-set file's parameter half is a **serialization of the parameter `ChangeList`** in a JSON shape this batch defines (not the CDFX XML — CDFX is only the *export* format), and the in-app parameter half is a plain `ChangeList` that is **re-resolved against the loaded A2L at selective-export time** to obtain the `ResolutionResult` the batch-03 CDFX writer requires. The unified file itself stores only the `ChangeList` and remains resolution-free; resolution is a transient, export-time computation, never persisted. The unified file is the working-document format; CDFX is the hand-off format. (Decision §6.2.1 OQ-3.) |

### 2.6 Source user stories

> Connextra format. Each US is traceable to one or more HLRs.

| ID | User Story | Source |
|----|------------|--------|
| US-001 | As a firmware engineer, I want to build a list of raw memory changes keyed by memory address, each holding the new bytes for that address, so that I can capture exactly which memory locations I intend to change, independent of the A2L. | batch-04 objective item 1 |
| US-002 | As a firmware engineer, I want each memory change validated against the loaded firmware image's address ranges, so that I am warned when an edit targets memory the image does not cover or is wider than the range — before I rely on it. | batch-04 objective; defaults note |
| US-003 | As a firmware engineer, I want each memory-change value shown in hex, ASCII and decimal, so that I can read and verify the bytes without manual conversion. | batch-04 objective item 1 |
| US-004 | As a firmware engineer, I want one container and one file that hold BOTH my A2L parameter changes and my raw memory changes, so that I can save, load and exchange a single working document for the whole patch set. | batch-04 objective items 2, 4 |
| US-005 | As a firmware engineer, I want to selectively export the unified change-set — a CDFX file for the parameter half and a separate JSON file for the memory-field half — so that I can hand each half to the tool that consumes it (vCDM for CDFX) without manual splitting. | batch-04 objective item 3 |

---

## 3. High-level requirements (HLR)

> This section specifies **9 HLRs** (HLR-001…HLR-009), each tracing to one or
> more of the 5 user stories of §2.6 and each decomposed into LLRs in §4
> (37 LLRs total — see §1.5 and the §4 header). The §5 validation strategy
> catalogues **37 active test cases over 37 IDs (TC-001…TC-037); there is no
> reserved/unallocated slot — TC-014 is allocated to the `MF-BAD-STRUCTURE`
> case**.

### HLR-001 — Memory-change model
- **Traceability:** US-001
- **Statement:** The system shall maintain a memory-change list in which each
  entry holds a memory start address and a contiguous run of one or more new
  byte values for that address, and shall support adding, editing and removing
  entries.
- **Rationale (informative):** The memory-change list is the second change kind
  the unified change-set composes; it must exist as a structured,
  address-keyed model before it can be validated, displayed, serialized or
  exported. It is the raw-memory peer of the batch-03 parameter `ChangeList`.
- **Validation:** test
- **Priority:** high

### HLR-002 — Memory-change validation against the loaded image ranges
- **Traceability:** US-002
- **Statement:** When a memory-change entry is added or edited, the system
  shall validate its address and byte-run length against the loaded firmware
  image's address ranges, and shall mark the entry with a validation status
  recording whether the addressed byte range lies fully inside, partially
  inside, or fully outside the loaded ranges — collecting one `ValidationIssue`
  per problem without aborting.
- **Rationale (informative):** Validating against the loaded image's ranges
  surfaces edits that target memory the image does not cover, mirroring the
  batch-03 `ResolutionStatus` / `ValidationIssue` collect-don't-abort pattern.
  The image is read-only input — the batch never applies the change (§6.2 DD-9).
- **Validation:** test
- **Priority:** high

### HLR-003 — Memory-change value display
- **Traceability:** US-003
- **Statement:** The system shall display each memory-change entry's stored
  bytes in hexadecimal as the primary form and shall additionally provide an
  ASCII rendering and a decimal rendering of the same bytes, derived for
  display only without mutating the stored bytes.
- **Rationale (informative):** Hex is the natural primary form for raw memory;
  ASCII and decimal companion views let the engineer verify the bytes against,
  for example, a string constant or a numeric field without manual conversion.
  This mirrors the batch-03 type-driven display (HLR-003 of batch-03) — here
  the form is driven by the raw-bytes nature of the data, not an A2L type.
- **Validation:** test+demo
- **Priority:** high

### HLR-004 — Unified change-set container
- **Traceability:** US-004
- **Statement:** The system shall provide one unified change-set container that
  holds both the batch-03 parameter `ChangeList` and the batch-04
  `MemoryChangeList`, and shall expose each half for independent inspection,
  mutation and export without merging the two.
- **Rationale (informative):** A single container is what makes one save, one
  load and one screen possible for the whole patch set; keeping the two halves
  distinct (a parameter change and a memory change are different kinds, keyed
  differently) is what makes selective export and the unchanged-CDFX-writer
  reuse possible.
- **Validation:** test
- **Priority:** high

### HLR-005 — Unified change-set file write
- **Traceability:** US-004
- **Statement:** When the engineer saves the unified change-set, the system
  shall write one JSON file, using the Python standard library `json` module,
  that holds both the parameter half and the memory-field half, placed inside
  the work area through the existing `workspace.py` containment path.
- **Rationale (informative):** One file for the whole working document is the
  US-004 deliverable; stdlib `json` satisfies the no-new-dependency constraint
  C-4 and is the convenient, human-inspectable format the owner asked for
  (§6.2.1 OQ-3). The work-area containment reuses the batch-03 LLR-007.7 path.
- **Validation:** test
- **Priority:** high

### HLR-006 — Unified change-set file read
- **Traceability:** US-004
- **Statement:** When the engineer loads a unified change-set file, the system
  shall parse the JSON into a unified change-set holding both halves, shall
  validate the file structurally, and shall collect every validation finding as
  a `ValidationIssue` without aborting the load.
- **Rationale (informative):** Reading must mirror the project's
  collect-don't-abort culture so a malformed or partially-corrupt file surfaces
  its problems as issues and still yields whatever parsed correctly, never a
  crash — consistent with the batch-03 CDFX reader (HLR-005/006 of batch-03).
- **Validation:** test
- **Priority:** high

### HLR-007 — Selective export to CDFX + memory-field JSON
- **Traceability:** US-005
- **Statement:** When the engineer requests a selective export of the unified
  change-set, the system shall produce a CDFX (`.cdfx`) file from the parameter
  half by invoking the unchanged batch-03 CDFX writer and shall produce a
  separate JSON file from the memory-field half, each placed inside the work
  area through the existing `workspace.py` containment path, and shall report
  the `ValidationIssue` results of each.
- **Rationale (informative):** Each half has a different consumer — vCDM
  consumes the CDFX parameter file, a memory-oriented tool or the engineer
  consumes the memory-field JSON — so the export must split, not merge.
  Reusing the batch-03 writer unchanged (constraint C-1) keeps the CDFX format
  contract stable and avoids re-implementation.
- **Validation:** test
- **Priority:** high

### HLR-008 — Memory-field file validation rule set
- **Traceability:** US-004, US-005
- **Statement:** The system shall apply a fixed, documented set of structural
  validation rules to the unified change-set file on read and to the
  memory-field export file on write, emitting one `ValidationIssue` with a
  stable code per rule violation.
- **Rationale (informative):** A fixed rule set with stable issue codes is what
  makes "valid unified file" and "valid memory-field file" testable and keeps
  the contract stable for tests — the same discipline the batch-03 `W-*` / `R-*`
  CDFX rule set established.
- **Validation:** test
- **Priority:** medium

### HLR-009 — Patch Editor memory-change management
- **Traceability:** US-001, US-003, US-004, US-005
- **Statement:** The system shall extend the Patch Editor rail screen so the
  engineer can add, edit and remove memory-field changes alongside the existing
  parameter changes, can save and load the unified change-set file, and can
  trigger the selective export — without removing or regressing the batch-03
  parameter-change controls.
- **Rationale (informative):** The Patch Editor is the single interactive
  surface for the whole patch set; the memory-change kind must be reachable
  from it, and the batch-03 parameter-change behaviour must survive the
  extension intact.
- **Validation:** test+demo
- **Priority:** high

---

## 4. Low-level requirements (LLR)

> This section specifies **37 LLRs**: 4 (LLR-001.x) + 5 (LLR-002.x) +
> 3 (LLR-003.x) + 5 (LLR-004.x) + 4 (LLR-005.x) + 5 (LLR-006.x) +
> 5 (LLR-007.x) + 3 (LLR-008.x) + 3 (LLR-009.x) = 37. Every LLR traces to
> exactly one parent HLR; every HLR (HLR-001…HLR-009) is decomposed here.

### LLR-001.1 — Memory-change entry data structure
- **Traceability:** HLR-001
- **Statement:** The memory-change model shall represent each entry as a
  structured record holding at least the fields `address` (a non-negative
  integer memory start address), `new_bytes` (an ordered, non-empty sequence of
  integer byte values, each in the range 0–255), and a validation-status field.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - An entry can be constructed with an address and a byte run and reports its
    fields.
  - An entry's byte run preserves order and length.
  - The entry exposes its addressed byte range as `(address, address + len(new_bytes))`.

### LLR-001.2 — Memory-change add / edit / remove operations
- **Traceability:** HLR-001
- **Statement:** The memory-change model shall provide operations to add an
  entry, edit the `new_bytes` of an existing entry identified by its `address`,
  and remove an entry identified by its `address`.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Adding then removing the same address leaves the list empty.
  - Editing an entry changes only that entry's `new_bytes`.

### LLR-001.3 — Memory-change entry identity and duplicate handling
- **Traceability:** HLR-001
- **Statement:** The memory-change model shall treat the `address` field as the
  entry identity, and when an add targets an address that already has an entry
  it shall update that entry in place rather than create a duplicate.
- **Rationale (informative):** Keying on the start address gives one
  authoritative entry per addressed location, mirroring the batch-03
  `ChangeList` `(name, index)` identity rule. Overlap *between* two distinct
  start addresses is a validation concern, not an identity concern — see
  LLR-002.4.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Adding the same address twice yields one entry with the latest bytes.

### LLR-001.4 — Memory-change ordering is deterministic
- **Traceability:** HLR-001
- **Statement:** The memory-change model shall expose its entries in a
  deterministic order so that repeated serialization of the same memory-change
  list produces byte-identical output.
- **Rationale (informative):** A deterministic order — insertion order or
  ascending address; the implementation picks one and pins it with a test —
  makes the unified-file write and the memory-field export reproducible, the
  same guarantee batch-03 LLR-001.4 gave the parameter `ChangeList`.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Two serializations of the same memory-change list produce identical
    entry order.

### LLR-002.1 — Validate a memory-change entry against the loaded image ranges
- **Traceability:** HLR-002
- **Statement:** The memory-change validation function shall test each entry's
  addressed byte range `(address, address + len(new_bytes))` against the loaded
  image's contiguous `(start, end)` address ranges and shall set the entry's
  validation status to `inside` when the addressed range lies fully within one
  loaded range, `partial` when it overlaps but is not contained within a single
  loaded range, and `outside` when it does not overlap any loaded range; an
  entry whose addressed byte range touches more than one loaded range — for
  example a run that begins inside one range, crosses an inter-range gap, and
  ends inside another range — shall receive the single status `partial` and
  shall be treated as one `partial` entry, not one status per touched range.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - An entry whose whole byte run falls inside a loaded range is `inside`.
  - An entry whose byte run starts inside a loaded range and runs past its end
    is `partial`.
  - An entry whose byte run falls in a gap between ranges is `outside`.
  - An entry whose byte run starts inside one loaded range, crosses a gap, and
    ends inside a second loaded range is a single `partial` entry.

### LLR-002.2 — Out-of-range and partial-range entries collect an issue, never abort
- **Traceability:** HLR-002
- **Statement:** If a memory-change entry's validation status is `partial` or
  `outside`, then the memory-change validation function shall append exactly
  one warning-level `ValidationIssue` for that entry describing the entry's
  address and the mismatch, and shall not raise an exception; an entry that is
  `partial` because its byte run touches more than one loaded range (LLR-002.1)
  shall still produce exactly one `ValidationIssue`. The issue message shall
  reference the entry's `address` and a count or summary of the byte run (for
  example "12 bytes") and shall not embed the raw `new_bytes` content verbatim.
- **Rationale (informative):** Collect-don't-abort: an out-of-range edit is
  recorded with a warning, never dropped or thrown — the engineer may still
  intend it, and applying it is deferred anyway (§6.2 DD-9). One entry yields
  one status and one issue regardless of how many loaded ranges its run
  touches, so the test-case count is deterministic. The raw `new_bytes` of a
  memory-change entry is firmware content the engineer intends to write;
  keeping it out of the message text keeps proprietary bytes out of the 5 MB
  rotating log (`.s19tool/logs/s19tui.log`) — see constraint C-9.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - An `outside` entry produces one warning `ValidationIssue` and the list
    remains usable.
  - A `partial` entry produces one warning `ValidationIssue`.
  - A gap-spanning entry that touches two loaded ranges produces exactly one
    warning `ValidationIssue`.
  - No `ValidationIssue` message string contains the entry's raw `new_bytes`
    content verbatim.

### LLR-002.3 — Validation without a loaded image
- **Traceability:** HLR-002
- **Statement:** While no firmware image is loaded, the memory-change
  validation function shall mark every memory-change entry with the status
  `unvalidated-no-image` and shall not raise an exception.
- **Rationale (informative):** Mirrors the batch-03 `unresolved-no-a2l` state
  (A2L-2): a memory-change list is still buildable and usable before an image
  is loaded; the entries are simply not yet validated.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - With no image, entries are still listed, all marked `unvalidated-no-image`.

### LLR-002.4 — Inter-entry overlap check
- **Traceability:** HLR-002
- **Statement:** The memory-change validation function shall append one
  warning-level `ValidationIssue` for each memory-change entry whose addressed
  byte range overlaps the addressed byte range of another entry, with a
  distinct `address`, in the same memory-change list, and shall not raise an
  exception; the issue message shall reference the overlapping entries'
  addresses and shall not embed the raw `new_bytes` content verbatim.
- **Rationale (informative):** Overlapping edits between two distinct start
  addresses are almost always a mistake (two entries writing the same byte);
  flagging them surfaces the conflict without merging or rejecting — the
  collect-don't-abort policy of §6.2.1 OQ-8 ("flagged, never merged/rejected").
  Overlap is a *validation* concern between two distinct identities; it is not
  an identity collision (two adds at the *same* `address` update in place — see
  LLR-001.3). A malformed `new_bytes` run is a different concern and a different
  failure mode — it is handled at construction time by LLR-002.5.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Two entries with distinct `address` keys whose byte ranges overlap each
    produce one overlap warning `ValidationIssue`; the list stays usable, no
    exception is raised.

### LLR-002.5 — Malformed `new_bytes` rejected at construction
- **Traceability:** HLR-002
- **Statement:** The memory-change model shall reject construction of a
  memory-change entry whose `new_bytes` run contains a byte value that is
  negative, a byte value that is greater than 255, or that is an empty run, by
  raising `ValueError`.
- **Rationale (informative):** A negative byte, a byte above 255, or an empty
  run is a malformed entry that does not describe a recordable edit intent —
  unlike an out-of-range *address*, which is a recordable intent that is
  flagged but kept (LLR-002.2). A malformed byte run is therefore rejected at
  construction with a hard `ValueError`, not collected as a `ValidationIssue`.
  The rejected cases are named explicitly — negative, greater than 255, empty —
  so each test assertion traces to an explicit normative phrase. This is the
  opposite failure mode from LLR-002.4 (collect-don't-abort), which is why the
  two concerns are stated as separate LLRs.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Constructing an entry with a byte value of `256` (greater than 255) raises
    `ValueError`.
  - Constructing an entry with a negative byte value raises `ValueError`.
  - Constructing an entry with an empty `new_bytes` run raises `ValueError`.

### LLR-003.1 — Hex display of the stored bytes
- **Traceability:** HLR-003
- **Statement:** The memory-change display function shall render an entry's
  stored `new_bytes` as a space-separated sequence of two-digit uppercase
  hexadecimal byte tokens, as the primary display form.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Bytes `[0x01, 0xAB, 0xFF]` render as `01 AB FF`.

### LLR-003.2 — ASCII and decimal companion renderings
- **Traceability:** HLR-003
- **Statement:** The memory-change display function shall additionally render
  the same `new_bytes` as an ASCII string — each byte in the printable ASCII
  range 0x20–0x7E shown as its character and every other byte shown as the
  single fixed placeholder character `.` (the period character, byte 0x2E) —
  and as a space-separated sequence of decimal byte values.
- **Rationale (informative):** ASCII lets the engineer recognise string
  content; decimal is the plain numeric companion. A non-printable byte is
  shown as the placeholder `.` rather than dropped, so the ASCII rendering
  keeps positional alignment with the hex rendering. The placeholder is pinned
  to `.` (0x2E) — the conventional hex-dump placeholder — so two
  implementations cannot disagree and both pass a test.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Bytes for `"AB"` (`[0x41, 0x42]`) render ASCII `AB` and decimal `65 66`.
  - A non-printable byte renders as the `.` placeholder character in the ASCII
    form.

### LLR-003.3 — Display derivation does not mutate stored bytes
- **Traceability:** HLR-003
- **Statement:** The memory-change display function shall derive the hex, ASCII
  and decimal renderings without modifying the entry's stored `new_bytes`.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - The stored `new_bytes` is byte-identical before and after any rendering
    call.

### LLR-004.1 — Unified change-set holds both halves
- **Traceability:** HLR-004
- **Statement:** The unified change-set container shall hold one parameter
  `ChangeList` instance and one `MemoryChangeList` instance, and shall expose
  each as a distinct attribute for independent access.
- **Rationale (informative):** The parameter half is held as a plain
  batch-03 `ChangeList` — it carries no `ResolutionResult` and no resolution
  state. Resolution against the loaded A2L is not part of the container or the
  on-disk unified file; it is a transient computation performed only at
  selective-export time so the batch-03 CDFX writer can be fed a typed
  `ResolutionResult` (LLR-007.1, LLR-007.5). Keeping the container and the
  unified file resolution-free is what lets the unified file be saved and
  reloaded without an A2L present (A-7, §6.2.1 OQ-3).
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A unified change-set exposes its parameter `ChangeList` and its
    `MemoryChangeList` separately.
  - The parameter half is a plain `ChangeList` carrying no `ResolutionResult`.

### LLR-004.2 — Unified change-set composes, does not subclass
- **Traceability:** HLR-004, (constraint C-3)
- **Statement:** The unified change-set container shall reference the existing
  batch-03 `ChangeList` type by composition and shall not subclass it, alter
  its behaviour, or modify `s19_app/tui/cdfx/changelist.py`.
- **Validation:** inspection
- **Acceptance criteria (informative):**
  - `changelist.py` is byte-unchanged by this batch; the unified container
    holds a `ChangeList` as a member.

### LLR-004.3 — Independent mutation of each half
- **Traceability:** HLR-004
- **Statement:** The unified change-set container shall allow a mutation of its
  memory-field half to leave its parameter half unchanged, and a mutation of
  its parameter half to leave its memory-field half unchanged.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Adding a memory change does not alter the parameter `ChangeList`.
  - Adding a parameter change does not alter the `MemoryChangeList`.

### LLR-004.4 — Unified change-set reports per-half counts
- **Traceability:** HLR-004
- **Statement:** The unified change-set container shall report the number of
  parameter-half entries and the number of memory-field-half entries
  separately.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - An empty unified change-set reports zero entries in each half.
  - After adding two memory changes and one parameter change, the counts are
    `(1, 2)`.

### LLR-004.5 — Unified change-set empty-state query
- **Traceability:** HLR-004
- **Statement:** The unified change-set container shall report whether it is
  empty, where empty means both the parameter half and the memory-field half
  have zero entries.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A unified change-set with no entries in either half reports empty.
  - A unified change-set with one memory change and no parameter change does
    not report empty.

### LLR-005.1 — Unified file JSON structure
- **Traceability:** HLR-005
- **Statement:** The unified change-set writer shall serialize the unified
  change-set to a single JSON document, using the standard library `json`
  module, containing a format-identifier field, a version field, a parameter
  half holding the parameter `ChangeList` entries, and a memory-field half
  holding the `MemoryChangeList` entries.
- **Rationale (informative):** A format identifier plus a version field lets
  the reader (LLR-006.x) recognise the file and tolerate future format
  revisions, the same self-describing discipline the CDFX `CATEGORY=CDF20`
  token gives the batch-03 format.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - The written file is valid JSON re-parseable by `json.loads`.
  - The document carries the format identifier, a version, a parameter half
    and a memory-field half.

### LLR-005.2 — Unified file encodes each parameter entry
- **Traceability:** HLR-005
- **Statement:** The unified change-set writer shall encode each parameter
  `ChangeList` entry in the parameter half with at least its `parameter_name`,
  `array_index`, `value` and resolution-status fields.
- **Rationale (informative):** The unified file is the working-document format;
  it carries the parameter entries in a plain JSON shape, distinct from the
  CDFX export format (§6.2.1 OQ-3). The fields chosen are exactly those of the
  batch-03 `ChangeListEntry`.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A parameter entry round-trips its `parameter_name`, `array_index` and
    `value` through the unified file.

### LLR-005.3 — Unified file encodes each memory-field entry
- **Traceability:** HLR-005
- **Statement:** The unified change-set writer shall encode the memory-field
  half of the unified file as a JSON **array of objects**, one object per
  memory-change entry, each object carrying `address` as an **integer-valued
  field** (a JSON number) and `new_bytes` as a JSON array of integers; the
  `address` shall not be encoded as a JSON object key, and a reader shall
  recover the exact integer `address` and the exact ordered byte sequence with
  no loss.
- **Rationale (informative):** This pins the on-disk wire format normatively
  and resolves §5.8 OQ-V1. JSON object *keys* are always strings — encoding
  `address` as an object key would force every reader to re-parse the key and
  would open an undocumented hex-vs-decimal ambiguity between writer and reader
  that the round-trip test (TC-025) could not catch if both sides happened to
  agree by accident. Encoding `address` as an integer-valued *field* inside an
  array element makes the integer survive natively through stdlib `json`. The
  in-app `MemoryChangeList` still keys entries by `address` (LLR-001.3
  identity) — that is the *in-memory* shape; this LLR pins only the *on-disk*
  shape.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A memory-change entry round-trips its `address` and `new_bytes` through the
    unified file with no loss.
  - The memory-field half of the written file is a JSON array of objects, each
    carrying `address` as a JSON number, never as a JSON object key.

### LLR-005.4 — Unified file write is work-area-contained
- **Traceability:** HLR-005, (constraint C-10)
- **Statement:** The unified change-set write path shall place the JSON file
  inside a `.s19tool/workarea/` root by reusing the existing `workspace.py`
  containment helper (`copy_into_workarea` / the batch-03
  `write_cdfx_to_workarea` staging pattern) unchanged: it shall serialize the
  unified change-set to a transient file under `.s19tool/workarea/temp/` and
  then call `copy_into_workarea` to place that file at the target. The write
  path shall reject a target that traverses a symbolic link or NTFS reparse
  point, shall dedup-suffix a colliding file name, and shall surface a
  containment rejection as a `ValidationIssue` rather than an uncaught
  exception.
- **Rationale (informative):** Reuses the batch-03 LLR-007.7 work-area
  containment guarantee verbatim; no new write path is introduced (constraint
  C-10). `copy_into_workarea` is a file-*copy* primitive — it takes an existing
  source file — whereas the unified writer holds in-memory JSON; the adaptation
  is to serialize to a transient `.s19tool/workarea/temp/` file first, then
  copy. The hardened containment primitive is reused exactly; containment and
  reparse-point checks are NOT re-inlined into a fresh write path, which
  constraint C-10 forbids.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A save produces a JSON file whose resolved path is under
    `.s19tool/workarea/`.
  - A reparse-point write target is rejected with a `ValidationIssue`, not a
    crash.

### LLR-006.1 — Unified file reader parses both halves
- **Traceability:** HLR-006
- **Statement:** The unified change-set reader shall parse a unified
  change-set JSON file with the standard library `json` module and shall
  reconstruct a unified change-set holding a parameter `ChangeList` populated
  from the parameter half and a `MemoryChangeList` populated from the
  memory-field half.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A unified file written by this batch round-trips back to an equivalent
    unified change-set.

### LLR-006.2 — Unified file reader tolerates malformed and mis-shaped JSON
- **Traceability:** HLR-006, HLR-008
- **Statement:** If a unified change-set file is not well-formed JSON, then the
  unified change-set reader shall emit one error-level `ValidationIssue` with
  the stable parse-error code `MF-JSON-PARSE` and shall return an empty unified
  change-set without raising an exception; this shall hold for a syntactically
  malformed document and for a document whose nesting is deep enough to make
  the standard library `json` parser raise `RecursionError` — the reader's
  exception handling shall catch `RecursionError` (a `RuntimeError`), not only
  `json.JSONDecodeError`. If a unified change-set file is well-formed JSON but
  does not carry the expected top-level parameter half and memory-field half
  (for example a bare `[]`, a bare `42`, a bare string, or an object with no
  recognised halves), then the reader shall emit one error-level
  `ValidationIssue` with the stable structural code `MF-BAD-STRUCTURE` and
  shall return an empty unified change-set without raising an exception — in
  particular without raising `KeyError`.
- **Rationale (informative):** Collect-don't-abort applies to every reader
  failure mode, not only to a truncated file. A deeply-nested JSON document is
  parsed by stdlib `json` via C recursion and raises `RecursionError` on
  overflow; `RecursionError` is a subclass of `RuntimeError`, not of
  `json.JSONDecodeError`, so an `except json.JSONDecodeError` clause alone
  would let it escape and crash the load — the handling must catch
  `RecursionError` explicitly. This resolves §5.8 OQ-V3 normatively. A
  well-formed-but-wrong-shape document trips neither a JSON parse error nor any
  per-entry rule (there are no entries to fail a per-entry rule); without the
  `MF-BAD-STRUCTURE` shape check a reader indexing the expected halves would
  raise an uncaught `KeyError` — the shape check closes that gap and keeps the
  reader within the collect-don't-abort contract.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A truncated / garbage file produces one `MF-JSON-PARSE` error
    `ValidationIssue` and no crash.
  - A deeply-nested JSON document produces one `MF-JSON-PARSE` error
    `ValidationIssue` and no uncaught `RecursionError`.
  - A well-formed JSON document missing the expected halves (`[]`, `42`,
    `{"foo": 1}`) produces one `MF-BAD-STRUCTURE` error `ValidationIssue`, an
    empty unified change-set, and no `KeyError`.

### LLR-006.3 — Unified file reader path resolution
- **Traceability:** HLR-006, (constraint C-10)
- **Statement:** When the unified change-set reader is invoked with a
  user-supplied file path, it shall resolve that path through
  `workspace.resolve_input_path` before opening the file, reusing the existing
  helper, and shall surface an unresolvable path as one error-level
  `ValidationIssue` rather than opening an arbitrary location.
- **Rationale (informative):** Reuses the batch-03 LLR-005.5 load-path
  discipline so path resolution is uniform with the rest of the app.
  `resolve_input_path` performs path *resolution* only — it walks the app cwd
  and the nearest repo root and checks `exists()`; it does **not** reject
  symbolic links or NTFS reparse points. Reading a unified file *through* a
  symbolic link is accepted as in-threat-model for a local single-user offline
  tool (assumption A-6): it is not a privilege escalation. The real read-path
  security boundary is the size cap (LLR-006.4), the decoded-structure ceiling
  (LLR-006.5) and the malformed/mis-shaped tolerance (LLR-006.2); the write-side
  containment (LLR-005.4, LLR-007.2) is the write boundary.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A valid unified-file path is resolved via `resolve_input_path` and read.
  - An unresolvable path yields one `ValidationIssue` and no file is opened.

### LLR-006.4 — Read-path size bound
- **Traceability:** HLR-006, HLR-008
- **Statement:** Before parsing, the unified change-set reader shall reject any
  unified change-set file whose on-disk byte size exceeds the documented cap of
  256 MB (`workspace.DEFAULT_COPY_SIZE_CAP_BYTES`) by emitting one error-level
  `ValidationIssue` and returning an empty unified change-set, without loading
  the file into memory.
- **Rationale (informative):** Reuses the batch-03 LLR-006.8 ingest cap so one
  consistent size limit governs every file the app reads. This cap bounds the
  *on-disk file*; it does not bound the *decoded in-memory structure* — see
  LLR-006.5.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A unified file larger than 256 MB produces one `ValidationIssue` and an
    empty unified change-set, and is not parsed into memory.

### LLR-006.5 — Read-path decoded-structure ceiling
- **Traceability:** HLR-006, HLR-008
- **Statement:** During reconstruction of a unified change-set from a parsed
  unified change-set file, the unified change-set reader shall enforce a
  documented ceiling on the number of memory-field entries and a documented
  ceiling on the length of any single `new_bytes` run; on a breach of either
  ceiling the reader shall emit one error-level `ValidationIssue` with the
  stable code `MF-ENTRY-LIMIT`, shall drop the offending entry and keep the
  remaining entries, and shall not raise an exception.
- **Rationale (informative):** The 256 MB on-disk size cap (LLR-006.4) bounds
  the file, not the decoded structure. A well-formed unified file comfortably
  under 256 MB can declare a `new_bytes` array of hundreds of millions of
  integers, or millions of memory-field entries — JSON integers and array
  overhead expand several-fold once parsed into Python `int` objects and lists,
  reaching multiple GB in memory from a sub-cap file. A ceiling enforced during
  reconstruction closes that resource-exhaustion vector that the file-size cap
  does not catch. Collect-don't-abort applies: the over-ceiling element is
  dropped, the rest of the change-set is kept, no exception is raised. The
  `MF-ENTRY-LIMIT` message shall reference the offending entry's `address` and
  a count, not the raw `new_bytes` content (consistent with LLR-002.2). The
  concrete numeric ceilings are pinned and documented in Phase 3 alongside the
  `MF-*` code spellings.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A unified file declaring more memory-field entries than the documented
    ceiling produces one `MF-ENTRY-LIMIT` issue and a non-empty change-set
    holding the entries within the ceiling, with no crash.
  - A unified file declaring a single `new_bytes` run longer than the
    documented ceiling produces one `MF-ENTRY-LIMIT` issue, drops that entry,
    keeps the rest, and does not raise.

### LLR-007.1 — Selective export produces the CDFX parameter file via the batch-03 writer
- **Traceability:** HLR-007, (constraint C-1)
- **Statement:** When a selective export is requested, the export coordinator
  shall produce the CDFX file for the parameter half by re-resolving the
  unified change-set's parameter `ChangeList` against the currently loaded A2L
  (LLR-007.5) and then invoking the unchanged batch-03 CDFX write path
  (`write_cdfx_to_workarea`) with that `ChangeList` and the resulting
  `ResolutionResult`, and shall not re-implement or modify CDFX serialization.
- **Rationale (informative):** The batch-03 `write_cdfx_to_workarea` entry
  point takes a mandatory `resolution: ResolutionResult` argument carrying the
  parameter entries resolved against the loaded A2L. The unified change-set
  holds the parameter half as a plain `ChangeList` with no `ResolutionResult`
  attached (LLR-004.1, A-7). To call the batch-03 writer unchanged (constraint
  C-1), the coordinator therefore re-resolves the `ChangeList` at export time
  (LLR-007.5) — mirroring how `cdfx_service` resolves before a CDFX write — and
  feeds the writer a freshly-computed `ResolutionResult`. The writer itself is
  still invoked literally unchanged; it is simply supplied a transient,
  export-time argument. The unified file format stays resolution-free
  (LLR-005.2).
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - The exported `.cdfx` is produced by a call into the batch-03 writer, fed a
    `ResolutionResult` obtained from the export-time re-resolution (LLR-007.5).
  - `s19_app/tui/cdfx/writer.py` is byte-unchanged by this batch.

### LLR-007.2 — Selective export produces the memory-field JSON file
- **Traceability:** HLR-007, (constraint C-10)
- **Statement:** When a selective export is requested, the export coordinator
  shall produce a separate JSON file from the unified change-set's
  `MemoryChangeList`, using the standard library `json` module, carrying a
  format-identifier field, a version field and the memory-change entries with
  their `address` and `new_bytes` (the memory-field half encoded as the JSON
  array-of-objects shape of LLR-005.3). The memory-field file write shall
  resolve under a `.s19tool/workarea/` root via the existing `workspace.py`
  containment path — serializing the JSON to a transient file under
  `.s19tool/workarea/temp/` and then calling `copy_into_workarea` to place it
  at the target — shall reject a target that traverses a symbolic link or NTFS
  reparse point, shall dedup-suffix a colliding file name, and shall surface a
  containment rejection as a `ValidationIssue` rather than an uncaught
  exception.
- **Rationale (informative):** The memory-field file is one of the three files
  this batch writes to disk; like the unified-file write (LLR-005.4) it must
  state its own write-path safety clause rather than rely on the looser wording
  of LLR-007.3. The clause mirrors LLR-005.4 verbatim — same containment path,
  same reparse-point rejection, same dedup-suffix — and reuses the hardened
  `copy_into_workarea` primitive unchanged via the serialize-to-temp-then-copy
  adaptation; constraint C-10 forbids re-inlining containment into a fresh
  write path.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - The memory-field export file is valid JSON carrying every memory-change
    entry.
  - The memory-field export file's resolved path is under `.s19tool/workarea/`.
  - A reparse-point write target for the memory-field file is rejected with a
    `ValidationIssue`, not a crash.

### LLR-007.3 — Selective export produces two distinct files
- **Traceability:** HLR-007
- **Statement:** When a selective export is requested, the export coordinator
  shall produce the CDFX parameter file and the memory-field JSON file as two
  distinct files, each placed inside the work area through the existing
  `workspace.py` containment path, and shall not merge the two halves into one
  file.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A selective export yields exactly two files — one `.cdfx`, one `.json` —
    both under `.s19tool/workarea/`.

### LLR-007.4 — Selective export collects and reports each half's issues
- **Traceability:** HLR-007, HLR-008
- **Statement:** The export coordinator shall collect the `ValidationIssue`
  results of the CDFX write and the `ValidationIssue` results of the
  memory-field write into one combined result and shall identify which half
  each issue came from by setting that issue's existing `ValidationIssue.artifact`
  field (for example `artifact="param-half"` and `artifact="memory-half"`),
  without aborting the export of one half because the other half produced
  issues.
- **Rationale (informative):** Each half exports independently; a problem in
  the parameter half (for example an unresolved entry the CDFX writer excludes)
  must not block the memory-field export, and vice versa — collect-don't-abort
  across the two halves. The per-half origin is carried on the existing
  `ValidationIssue.artifact` field (the field LLR-008.3 already says identifies
  the producing concern) — no new field and no `ValidationIssue` model change
  is introduced, consistent with constraint C-5.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - An export where the parameter half has an excluded entry still produces the
    memory-field file and reports the parameter-half warning.
  - Each combined-result issue carries an `artifact` value identifying its
    originating half.

### LLR-007.5 — Export-time re-resolution of the parameter half
- **Traceability:** HLR-007, (constraint C-1)
- **Statement:** Immediately before the CDFX write of LLR-007.1, the export
  coordinator shall re-resolve the unified change-set's parameter `ChangeList`
  against the currently loaded A2L by reusing the batch-03 `resolve_against_a2l`
  resolution path, producing a `ResolutionResult` for the parameter half; while
  no A2L is loaded the coordinator shall mirror the batch-03 `unresolved-no-a2l`
  behaviour — producing an unresolved `ResolutionResult`, collecting one
  `ValidationIssue` rather than aborting, and not raising an exception.
- **Rationale (informative):** The batch-03 CDFX writer requires a typed
  `ResolutionResult`; the unified change-set carries only a plain `ChangeList`
  (LLR-004.1, A-7), so the coordinator must compute the `ResolutionResult` at
  export time. Re-resolving against the loaded A2L through the existing
  `resolve_against_a2l` path — the same path `cdfx_service` uses before a CDFX
  write — reuses batch-03 machinery rather than inventing a new resolver, keeps
  the batch-03 writer literally unchanged (constraint C-1), and keeps the
  unified file format resolution-free (LLR-005.2). Re-resolution is a transient
  export-time computation; its result is passed to the writer and never
  persisted to the unified file. With no A2L loaded the export still proceeds
  with an unresolved result, mirroring the `unresolved-no-a2l` collect-don't-
  abort pattern (assumption A-2).
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - With an A2L loaded, a selective export re-resolves the parameter half via
    `resolve_against_a2l` and feeds the resulting `ResolutionResult` to the
    CDFX writer.
  - With no A2L loaded, the export produces an unresolved `ResolutionResult`,
    collects a `ValidationIssue`, and does not raise.

### LLR-008.1 — Memory-field structural validation rule set
- **Traceability:** HLR-008
- **Statement:** The unified change-set reader and the memory-field reader
  shall apply a fixed set of structural rules to each memory-field entry —
  a present non-negative integer `address`, a present non-empty `new_bytes`
  sequence, and every byte value within 0–255 — emitting one `ValidationIssue`
  with a stable code per rule violation.
- **Rationale (informative):** These are the *per-entry* structural rules. The
  fixed `MF-*` rule-code set this batch defines spans both the per-entry rules
  here and the whole-document and resource rules of the readers: the
  whole-document `MF-JSON-PARSE` and `MF-BAD-STRUCTURE` codes are specified in
  LLR-006.2, the resource-bound `MF-SIZE-CAP` in LLR-006.4, the
  decoded-structure `MF-ENTRY-LIMIT` in LLR-006.5, the path code
  `MF-PATH-UNRESOLVED` in LLR-006.3, and the version code `MF-VERSION-UNKNOWN`
  in LLR-008.2. The complete `MF-*` set is fixed and documented (HLR-008); the
  concrete code spellings are pinned in Phase 3.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A memory-field entry missing its `address` produces one issue with the
    documented code.
  - A memory-field entry with a byte value outside 0–255 produces one issue.

### LLR-008.2 — Unsupported or unknown file version is tolerated
- **Traceability:** HLR-008
- **Statement:** If a unified change-set file or a memory-field file declares a
  version token the reader does not recognise, then the reader shall emit one
  info-level `ValidationIssue` recording the unknown version and shall continue
  parsing the file.
- **Rationale (informative):** Version tolerance mirrors the batch-03
  `R-VERSION-UNKNOWN` rule: an unknown version is informational, not fatal, so
  a file from a future format revision still loads what it can.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A file with an unrecognised version token reads its entries and produces
    one info `ValidationIssue`.

### LLR-008.3 — Issues reuse the project ValidationIssue model
- **Traceability:** HLR-008, (constraint C-5)
- **Statement:** Every validation finding produced by the memory-change
  validator, the unified change-set reader/writer and the memory-field
  reader/writer shall be a `ValidationIssue` (`s19_app/validation/model.py`)
  whose `artifact` field identifies the producing concern, and whose `severity`
  shall round-trip through `color_policy.css_class_for_severity`.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A memory-field issue's severity yields a valid `sev-*` CSS class.

### LLR-009.1 — Patch Editor renders the memory-change list
- **Traceability:** HLR-009
- **Statement:** The Patch Editor screen shall render the current
  memory-change list as a row per entry showing the memory address, the hex
  rendering of the new bytes, and the entry's validation status, presented
  alongside the existing parameter-change rows without removing them.
- **Validation:** test (integration)
- **Acceptance criteria (informative):**
  - Adding a memory change adds a visible memory-change row.
  - The batch-03 parameter-change rows remain visible and functional.

### LLR-009.2 — Patch Editor memory-change controls are wired
- **Traceability:** HLR-009
- **Statement:** The Patch Editor screen shall wire its memory-change controls
  — an address input, a new-bytes input, and add / edit / remove actions — to
  the memory-change model through the service layer, and `app.py` shall contain
  only the UI-state wiring that calls the service.
- **Rationale (informative):** Mirrors the batch-03 LLR-007.2 / LLR-007.5
  pattern — the screen posts an action message, the service performs the model
  work, `app.py` holds no model or serialization logic (constraint C-7).
- **Validation:** test (integration)
- **Acceptance criteria (informative):**
  - Submitting the memory-change inputs mutates the memory-change list and
    updates the rendered rows.
  - No JSON parsing/serialization or model logic is added to `app.py`.

### LLR-009.3 — Patch Editor save / load / selective-export actions are wired
- **Traceability:** HLR-009
- **Statement:** The Patch Editor screen shall provide actions to save the
  unified change-set file, to load a unified change-set file, and to trigger
  the selective export, each invoking the corresponding service operation and
  surfacing its `ValidationIssue` results through the existing status path.
- **Validation:** test (integration)
- **Acceptance criteria (informative):**
  - The save action produces a unified change-set file under
    `.s19tool/workarea/` and reports issues.
  - The load action populates both halves and surfaces read issues; a
    malformed file does not crash the screen.
  - The selective-export action produces the `.cdfx` and the memory-field JSON
    file and reports issues.

---

## 5. Validation Strategy

> Owned by the qa-reviewer pass. This section assigns a validation method to
> every HLR and LLR, defines the `TC-NNN` test cases with bidirectional
> traceability, specifies the synthetic fixtures — firmware images, unified
> change-set files, memory-field files — records the round-trip and rule-code
> test approach, flags weakly-testable requirements, and states the batch
> acceptance criteria. The architect's per-HLR `Validation` field (Section 3)
> and per-LLR `Validation` field (Section 4) were treated as input; the method
> assignment below is authoritative for Phases 2–4. This batch mirrors the
> style of the batch-03 Section 5 validation strategy.

### 5.1 Methods

- **test** — automated execution under `pytest`. The default for every LLR.
  Three sub-kinds are used:
  - **test (unit)** — exercises a function/class of the memory-change model,
    the unified change-set container, or the JSON read/write/export modules
    directly, with synthetic in-memory or `tmp_path` inputs. No Textual app
    instance.
  - **test (integration)** — drives the extended Patch Editor through a real
    `S19TuiApp` instance headlessly via `App.run_test()` and the Textual
    `pilot`, the established harness pattern of `tests/test_tui_directionb.py`
    and `tests/test_tui_patch_editor.py`.
  - **test (round-trip)** — a unit test whose verdict is structural equality
    between a unified change-set and the unified change-set recovered after a
    write→read cycle. Called out separately because it is the strongest
    correctness check (see §5.5).
- **demo** — observed execution of behavior. Used to corroborate the two
  UX-oriented HLRs (HLR-003 value display, HLR-009 functional screen); the
  demo script is produced in Phase 6, not a pass/fail gate.
- **inspection** — static review of code against a written checklist. Used
  where there is no objective runtime assertion: LLR-004.2 (the
  compose-not-subclass constraint C-3) and LLR-009.2's `app.py`-clean clause
  (constraint C-7). The inspection checklist is inline in §5.6 so the verdict
  is not reviewer-subjective.
- **analysis** — quantitative/structural reasoning. Used only as a
  corroborating method — for the read-path size-bound case TC-022 (the
  `DEFAULT_COPY_SIZE_CAP_BYTES` argument) — see §5.5 and §5.7.

A single requirement may carry a primary method plus a corroborating method;
the per-requirement table (§5.2 / §5.3) lists both.

### 5.2 Per-HLR validation-method table

| Requirement | Primary | Corroborating | Test Case ID(s) | Notes |
|-------------|---------|---------------|-----------------|-------|
| HLR-001 — Memory-change model | test | — | TC-001, TC-002, TC-003, TC-004 | Entry construction, address-range identity, add/edit/remove and deterministic ordering are model-level facts assertable in unit tests. |
| HLR-002 — Memory-change validation against the loaded image ranges | test | — | TC-005, TC-006, TC-007, TC-008 | The `inside` / `partial` / `outside` / `unvalidated-no-image` status, the gap-spanning single-`partial` case, the overlap check and the malformed-`new_bytes` rejection are discrete, assertable outcomes; collect-don't-abort is asserted by a usable list after a flag. |
| HLR-003 — Memory-change value display | test | demo | TC-009, TC-010, TC-011 | Hex / ASCII / decimal rendering of a fixed byte run is a deterministic mapping; demo corroborates the rendered forms read naturally. |
| HLR-004 — Unified change-set container | test | inspection | TC-012, TC-013, TC-026, TC-027 | Per-half access, independent mutation, counts and empty-state are unit-assertable; the compose-not-subclass clause (LLR-004.2) is verified by inspection (TC-027). |
| HLR-005 — Unified change-set file write | test | test (round-trip) | TC-015, TC-016, TC-017, TC-018, TC-025 | The written JSON structure is asserted field-by-field; TC-025 round-trip corroborates write correctness end-to-end. |
| HLR-006 — Unified change-set file read | test | test (round-trip) | TC-014, TC-019, TC-020, TC-021, TC-022, TC-025, TC-035, TC-037 | Parsing valid, malformed, mis-shaped, deeply-nested, mis-pathed, oversized and over-ceiling files are all assertable; TC-025 round-trip corroborates read correctness. |
| HLR-007 — Selective export to CDFX + memory-field JSON | test | — | TC-028, TC-029, TC-030, TC-031, TC-036 | The two-file split, the unchanged-CDFX-writer reuse, the export-time re-resolution and the cross-half issue collection are each assertable; the writer-unchanged clause is also covered by the §5.6 checklist. |
| HLR-008 — Memory-field file validation rule set | test | — | TC-014, TC-020, TC-022, TC-023, TC-024, TC-035, TC-037 | Each `MF-*` rule code is provoked by a crafted fixture and asserted with its documented code and severity. |
| HLR-009 — Patch Editor memory-change management | test | demo | TC-032, TC-033, TC-034 | The screen render/edit/save/load/export behavior is driven via `App.run_test()`; demo corroborates the screen is a working tool. |

### 5.3 Per-LLR validation-method table

| Requirement | Method | Test Case ID(s) | Notes |
|-------------|--------|-----------------|-------|
| LLR-001.1 — Memory-change entry data structure | test (unit) | TC-001 | Entry holds `address` (non-negative int), `new_bytes` (ordered, non-empty, each 0–255) and a validation-status field; exposes `(address, address+len(new_bytes))` as its addressed range. |
| LLR-001.2 — Add / edit / remove operations | test (unit) | TC-002 | Add-then-remove of one address leaves the list empty; edit mutates only the targeted entry's `new_bytes`. |
| LLR-001.3 — Entry identity and duplicate handling | test (unit) | TC-002 | Adding the same `address` twice updates in place — one entry, latest bytes. |
| LLR-001.4 — Memory-change ordering is deterministic | test (unit) | TC-003 | Two serializations of the same memory-change list produce identical entry order. |
| LLR-002.1 — Validate an entry against the loaded image ranges | test (unit) | TC-005 | A whole-run-inside entry is `inside`; a run crossing a range end is `partial`; a run in a gap is `outside`; a run that starts in range 1, crosses the gap and ends in range 2 is a single `partial` entry; the validator reads `LoadedFile.ranges`, no firmware re-parse. |
| LLR-002.2 — Out-of-range / partial entries collect an issue, never abort | test (unit) | TC-006 | An `outside`, a `partial` and a gap-spanning entry each produce exactly one warning `ValidationIssue`; the list stays usable, no exception. |
| LLR-002.3 — Validation without a loaded image | test (unit) | TC-007 | With no image, every entry is `unvalidated-no-image`; no exception; the list is still buildable. |
| LLR-002.4 — Inter-entry overlap check | test (unit) | TC-008 | Two entries with distinct `address` keys whose addressed byte ranges intersect each produce exactly one overlap warning `ValidationIssue`; the list stays usable, no exception (TC-008 overlap arm). |
| LLR-002.5 — Malformed `new_bytes` rejected at construction | test (unit) | TC-008 | Constructing an entry with a negative byte value, a byte value greater than 255, or an empty `new_bytes` run raises `ValueError` (TC-008 `ValueError` arms). |
| LLR-003.1 — Hex display of the stored bytes | test (unit) | TC-009 | `[0x01,0xAB,0xFF]` renders as `01 AB FF` — uppercase, two-digit, space-separated. |
| LLR-003.2 — ASCII and decimal companion renderings | test (unit) | TC-010 | `[0x41,0x42]` renders ASCII `AB` and decimal `65 66`; a non-printable byte renders as the exact placeholder character `.` (`0x2E`) pinned in LLR-003.2, keeping positional alignment. |
| LLR-003.3 — Display derivation does not mutate stored bytes | test (unit) | TC-011 | Stored `new_bytes` is byte-identical before and after every rendering call. |
| LLR-004.1 — Unified change-set holds both halves | test (unit) | TC-012 | The container exposes a `ChangeList` and a `MemoryChangeList` as distinct attributes for independent access. |
| LLR-004.2 — Unified change-set composes, does not subclass | inspection | TC-027 | `changelist.py` is byte-unchanged; the container holds a `ChangeList` as a member, not a subclass — §5.6 checklist. |
| LLR-004.3 — Independent mutation of each half | test (unit) | TC-013 | Adding a memory change leaves the parameter `ChangeList` unchanged, and vice versa. |
| LLR-004.4 — Unified change-set reports per-half counts | test (unit) | TC-013 | An empty container reports `(0,0)`; after two memory + one parameter change the counts are `(1,2)`. |
| LLR-004.5 — Unified change-set empty-state query | test (unit) | TC-013 | An empty container reports empty; one memory change with no parameter change does not report empty. |
| LLR-005.1 — Unified file JSON structure | test (unit) | TC-015 | The written file is valid JSON re-parseable by `json.loads` and carries a format identifier, a version, a parameter half and a memory-field half. |
| LLR-005.2 — Unified file encodes each parameter entry | test (unit) | TC-016 | A parameter entry round-trips its `parameter_name`, `array_index` and `value` (and resolution-status) through the unified file. |
| LLR-005.3 — Unified file encodes each memory-field entry | test (unit) | TC-017 | A memory-change entry round-trips its exact integer `address` and exact ordered `new_bytes` through the unified file with no loss. |
| LLR-005.4 — Unified file write is work-area-contained | test (unit) | TC-018 | A save produces a JSON file resolving under `.s19tool/workarea/`; a reparse-point write target is rejected with a `ValidationIssue`; a colliding name is dedup-suffixed; no crash. |
| LLR-006.1 — Unified file reader parses both halves | test (unit), test (round-trip) | TC-019, TC-025 | A unified file written by this batch round-trips back to an equivalent unified change-set (TC-025 is the round-trip verdict). |
| LLR-006.2 — Unified file reader tolerates malformed and mis-shaped JSON | test (unit) | TC-020, TC-014, TC-035 | A truncated/garbage file → exactly one `MF-JSON-PARSE` error issue, an empty unified change-set, no exception (TC-020); a well-formed-but-wrong-shape document → one `MF-BAD-STRUCTURE` issue, empty change-set, no `KeyError` (TC-014); a deeply-nested document → one `MF-JSON-PARSE` issue, empty change-set, no escaping `RecursionError` (TC-035). |
| LLR-006.3 — Unified file reader path resolution | test (unit) | TC-021 | A valid path is resolved via `resolve_input_path` and read; an unresolvable path yields exactly one error `ValidationIssue` and no file is opened. |
| LLR-006.4 — Read-path size bound | test (unit), analysis | TC-022 | A unified file whose probed byte size exceeds the 256 MB `DEFAULT_COPY_SIZE_CAP_BYTES` cap → one error issue, an empty unified change-set, and the file is never loaded into memory. |
| LLR-006.5 — Read-path decoded-structure ceiling | test (unit) | TC-037 | A file declaring more memory-field entries than the documented ceiling, or a single `new_bytes` run longer than the documented ceiling, → one `MF-ENTRY-LIMIT` issue per breach, the offending entry dropped, the rest kept, no exception. |
| LLR-007.1 — Selective export produces the CDFX file via the batch-03 writer | test (unit) | TC-028, TC-030 | The `.cdfx` is produced by a call into the unchanged `write_cdfx_to_workarea`; `writer.py` is byte-unchanged. |
| LLR-007.2 — Selective export produces the memory-field JSON file | test (unit) | TC-029 | The memory-field export file is valid JSON carrying a format identifier, a version and every memory-change entry's `address` and `new_bytes`. |
| LLR-007.3 — Selective export produces two distinct files | test (unit) | TC-028 | A selective export yields exactly two files — one `.cdfx`, one `.json` — both under `.s19tool/workarea/`, never merged. |
| LLR-007.4 — Selective export collects and reports each half's issues | test (unit) | TC-031 | An export where the parameter half has an excluded entry still produces the memory-field file and reports the parameter-half warning, tagged with its originating half. |
| LLR-007.5 — Export-time re-resolution of the parameter half | test (unit) | TC-036 | With an A2L loaded, the export re-resolves the parameter `ChangeList` via `resolve_against_a2l` and feeds the resulting `ResolutionResult` to the CDFX writer; with no A2L loaded, the export produces an unresolved `ResolutionResult`, collects one `ValidationIssue`, and does not raise. |
| LLR-008.1 — Memory-field structural validation rule set | test (unit) | TC-023 | A memory-field entry missing its `address`, with an empty `new_bytes`, or with a byte value outside 0–255 each produces one `ValidationIssue` with the documented `MF-*` code. |
| LLR-008.2 — Unsupported or unknown file version is tolerated | test (unit) | TC-024 | A file with an unrecognised version token reads its entries and produces exactly one info `MF-VERSION-UNKNOWN` issue. |
| LLR-008.3 — Issues reuse the project ValidationIssue model | test (unit) | TC-022 | Every memory-change / unified / memory-field finding is a `ValidationIssue` whose `artifact` identifies the producing concern and whose `severity` round-trips through `css_class_for_severity` to a valid `sev-*` class. |
| LLR-009.1 — Patch Editor renders the memory-change list | test (integration) | TC-032 | Adding a memory change adds a visible memory-change row (address, hex, status); the batch-03 parameter-change rows remain visible. |
| LLR-009.2 — Patch Editor memory-change controls are wired | test (integration), inspection | TC-033, TC-027 | Submitting the address / new-bytes inputs mutates the memory-change list and re-renders the rows; no JSON parse/serialize or model logic in `app.py` (§5.6 checklist). |
| LLR-009.3 — Patch Editor save / load / selective-export actions are wired | test (integration) | TC-034 | Save produces a unified file under `.s19tool/workarea/` and reports issues; load populates both halves and surfaces read issues without crashing on a malformed file; selective export produces the `.cdfx` + memory-field JSON and reports issues. |

### 5.4 Test fixtures — synthetic data only

Per constraint C-9 and the batch-03 `R-TUI-034` rule, every firmware image,
`.cdfx`, unified change-set file, memory-field file and change-list fixture is
**synthetic** — generated in-test or via `tests/conftest.py`-style generators.
No client firmware / A2L / CDFX / change-set artifact is used. The new fixture
set is to live in `tests/conftest.py` alongside the existing
`make_large_s19/a2l/mac` and `change_list_factory` generators and follow the
same style (`seed: int = 0` default, programmatic content, no static binary
files on disk).

| Fixture / generator | Produces | Used by |
|---------------------|----------|---------|
| `memory_change_factory` | An in-memory `MemoryChangeList` builder yielding, on demand: an entry whose run is fully inside a known loaded range; an entry whose run starts inside and crosses a range end (`partial`); an entry whose run falls in a gap between ranges (`outside`); a **gap-spanning** entry whose run starts inside range 1, crosses the inter-range gap, and ends inside range 2 (the single-`partial`, single-issue multi-range case of LLR-002.1 / LLR-002.2); and an **overlap** pair — two entries built at **distinct** start addresses whose byte runs intersect, pinned concretely as `address 0x100 len 8` (range `[0x100, 0x108)`) and `address 0x104 len 8` (range `[0x104, 0x10C)`). The two overlap entries have distinct `address` keys, so the LLR-001.3 identity rule does not collapse them into one entry and the overlap warning is genuinely provoked. All addresses are chosen relative to the `make_ranged_s19` defaults so the `inside`/`partial`/`outside`/gap-spanning outcome is deterministic. | TC-001…TC-008, TC-012, TC-013 |
| `make_ranged_s19` | A tiny synthetic S19 (reusing the `_s19_data_record` / `_s19_header_record` / `_s19_terminator` helpers) with **two known, disjoint, gap-separated address ranges** — small enough to enumerate, with the gap and the post-last-range address documented so the `partial` / `outside` cases land exactly. Loaded through `load_service` to a `LoadedFile` so the validator consumes the real `ranges` snapshot, not a hand-built stub. | TC-005, TC-006, TC-008, TC-032 |
| `unified_changeset_factory` | An in-memory `UnifiedChangeSet` builder composing a `change_list_factory` parameter half (scalar + 1-D array + ASCII + the three adversarial IEEE floats) and a `memory_change_factory` memory half (inside + partial + outside + a multi-byte ASCII-string run). The three adversarial IEEE floats (`0.1`, the `5e-324` denormal, a 17-significant-digit value) are **inherited from the batch-03 `change_list_factory`** — this factory adds no float content of its own; the inheritance depends on batch-03 being merged and green (precondition A-1 / risk RK-2). The single source object for the round-trip TC-025. | TC-012, TC-013, TC-015…TC-019, TC-025, TC-028…TC-031, TC-036 |
| `make_unified_file` | A well-formed unified change-set JSON file on `tmp_path` carrying a format identifier, a version, a populated parameter half and a populated memory-field half — the §5 minimal example of the unified format. | TC-019, TC-021, TC-025 |
| `make_malformed_unified_file` | A truncated / non-well-formed JSON byte stream written to `tmp_path`. | TC-020 |
| `make_rule_violation_unified_file` | A parametrized generator emitting one unified / memory-field JSON file per `MF-*` structural rule, each crafted to trip exactly that rule (missing `address`, empty `new_bytes`, byte value outside 0–255, unknown version token). **For the per-entry rules, every variant also carries one valid memory-field entry alongside the violating element**, so TC-023 can assert the valid sibling is still recovered (the collect-don't-abort intent). It also emits the **`MF-BAD-STRUCTURE`** whole-document variants — well-formed JSON whose top-level shape carries no recognised parameter / memory-field halves (`[]`, `42`, `{"foo": 1}`) — used by TC-014; these whole-document variants carry no sibling entry, because the wrong-shape document has no entries at all. | TC-014, TC-023, TC-024 |
| `make_oversized_unified_file` | A unified change-set file whose probed on-disk size exceeds the 256 MB `DEFAULT_COPY_SIZE_CAP_BYTES` cap. The fixture **need not write a real 256 MB file** — it exposes the **size-probe seam**: the reader obtains the candidate's byte size through an injectable size-probe (e.g. a `size_probe` callable defaulting to `Path.stat().st_size`) which the test substitutes with a stub returning an over-cap value, so the size-reject path is exercised against a small on-disk file and the test stays fast. (Reuses the batch-03 `make_oversized_cdfx` seam pattern.) | TC-022 |
| `make_deeply_nested_unified_file` | A **small** unified change-set JSON file on `tmp_path` (a few hundred KB, far under the 256 MB cap) whose JSON structure is **programmatically nested** deep enough — on the order of 100,000 levels — to make the stdlib `json` parser raise `RecursionError`. Generated by emitting a long run of opening brackets so no static binary file is committed. The fixture exercises the LLR-006.2 `RecursionError`-catch clause: nesting depth, not file size, is the attack dimension. | TC-035 |
| `make_over_ceiling_unified_file` | A parametrized generator emitting two **small** well-formed unified change-set JSON files: one declaring **more memory-field entries than the documented LLR-006.5 ceiling**, and one declaring a single `new_bytes` run **longer than the documented per-run ceiling**. Each file stays well under the 256 MB cap — the decoded-structure ceiling, not the file-size cap, is what trips. Each file also carries valid in-ceiling entries alongside the offending element so TC-037 can assert the offending entry is dropped and the rest kept. The numeric ceilings are read from the same documented constants the reader enforces (pinned in Phase 3). | TC-037 |
| `make_patch_a2l` (reused from batch-03) | A small synthetic A2L with named scalar, 1-D array and ASCII characteristics, so the parameter half resolves and the CDFX export emits `SW-INSTANCE`s. | TC-028, TC-030, TC-031, TC-034, TC-036 |

> **`MF-*` rule codes.** The batch-03 CDFX rule set used `W-*` (write) / `R-*`
> (read) prefixes. Batch-04's memory-field / unified-file structural rule codes
> use the **`MF-*`** prefix (`MF-JSON-PARSE`, `MF-BAD-STRUCTURE`,
> `MF-NO-ADDRESS`, `MF-EMPTY-BYTES`, `MF-BYTE-RANGE`, `MF-VERSION-UNKNOWN`,
> `MF-SIZE-CAP`, `MF-ENTRY-LIMIT`, `MF-PATH-UNRESOLVED`) so the two batches'
> codes never collide and the unified-file contract is greppable.
> `MF-BAD-STRUCTURE` flags a well-formed-but-wrong-shape document (LLR-006.2)
> and `MF-ENTRY-LIMIT` flags a decoded-structure-ceiling breach (LLR-006.5).
> The concrete code spelling is an implementation detail to be pinned in
> Phase 3; the tests assert on whatever stable codes the implementation
> documents, and Phase 2 confirms the code set is fixed and documented
> (HLR-008).

### 5.5 Round-trip and read-path test approach

**Round-trip (TC-025) — the strongest correctness test.** TC-025 builds a
`UnifiedChangeSet` via `unified_changeset_factory` — a parameter half with at
least one resolved scalar, one 1-D array, one ASCII entry **and the three
adversarial IEEE float entries** (`0.1`, the denormal `5e-324`, a
17-significant-digit value, carried by `change_list_factory`), and a
memory-field half with at least one `inside`, one `partial`, one `outside`
entry and one multi-byte run — writes it to a `tmp_path` unified JSON file with
the unified writer, reads that file back with the unified reader, and asserts
the recovered `UnifiedChangeSet` is **structurally equal** to the original:

- **Parameter half:** same set of `(parameter_name, array_index)` keys —
  including the `Optional[int]` shape (scalar/string entries recover
  `array_index = None`, an N-element array recovers exactly `(name, 0)…(name,
  N-1)`) — same per-entry values asserted with **exact equality (`==`), no
  float tolerance**. The adversarial floats round-trip exactly only if the JSON
  encoding preserves full binary64 precision; the stdlib `json` module already
  emits `float` via `repr()`-equivalent text and decodes back to the same
  binary64, so the assertion can genuinely fail if a future change introduces a
  lossy intermediate string conversion. (This reuses the batch-03 adversarial-
  float rationale; the JSON path inherits it for free, and TC-025 pins it.)
- **Memory-field half:** same set of `address` keys, each entry's `new_bytes`
  recovered as the **exact ordered integer sequence** (a memory-field defect
  that drops, reorders, truncates or re-bases a byte run fails here).
- **Order:** the deterministic entry order of each half (LLR-001.4) is
  preserved, so two writes of the round-tripped object are byte-identical.

TC-025 is the corroborating verdict for HLR-005 and HLR-006 and the primary
verdict for LLR-006.1. Any write defect that produces a mis-shaped or
value-losing half, and any read defect that drops or mis-decodes an entry,
fails this single assertion.

**Malformed-read (TC-020) — collect-don't-abort.** TC-020 feeds
`make_malformed_unified_file` (a truncated / garbage JSON byte stream) to the
unified reader and asserts the reader surfaces **exactly one** `MF-JSON-PARSE`
error `ValidationIssue`, returns an **empty unified change-set**, and **raises
no exception** — the project's collect-don't-abort culture, mirroring the
batch-03 CDFX-reader `R-XML-PARSE` case (TC-016 of batch-03). The verdict is
the deterministic presence of the issue plus the no-raise, not a timeout.

**Read-path size bound (TC-022).** TC-022 covers LLR-006.4 — the
plain-but-huge resource-exhaustion vector. It uses `make_oversized_unified_file`
and the fixture's **size-probe seam**: the test substitutes the reader's
injectable size-probe with a stub reporting an over-256 MB byte size, so a
small on-disk file exercises the pre-parse size-reject path without writing a
real 256 MB file. The assertion is deterministic — an over-cap probe yields
exactly one `MF-SIZE-CAP` issue, an empty unified change-set, and `json.load`
is **never reached** (the size check precedes it, asserted via a no-open / no-
parse spy on the seam). The `analysis` corroboration records that the 256 MB
cap is the same `DEFAULT_COPY_SIZE_CAP_BYTES` constant the batch-03 ingest path
uses, so one consistent size limit governs every file the app reads, and that
no new dependency is introduced.

**Mis-shaped and deeply-nested read (TC-014, TC-035) — collect-don't-abort
beyond a truncated file.** TC-014 feeds the unified reader the
`MF-BAD-STRUCTURE` variants of `make_rule_violation_unified_file` — well-formed
JSON whose top-level shape carries no recognised halves (`[]`, `42`,
`{"foo": 1}`) — and asserts the reader emits **exactly one** `MF-BAD-STRUCTURE`
error `ValidationIssue`, returns an **empty unified change-set**, and **does not
raise** — in particular raises **no `KeyError`** from indexing an absent half.
TC-035 feeds `make_deeply_nested_unified_file` and asserts the reader surfaces
**exactly one** `MF-JSON-PARSE` error `ValidationIssue`, returns an **empty
unified change-set**, and **does not let a `RecursionError` escape** — the
reader's exception handling catches `RecursionError` (a `RuntimeError`), not
only `json.JSONDecodeError`. Both verdicts are the deterministic presence of
the issue plus the no-raise.

**Decoded-structure ceiling (TC-037).** TC-037 covers LLR-006.5 — a
resource-exhaustion vector the 256 MB on-disk size cap does **not** catch. It
uses `make_over_ceiling_unified_file` and asserts that a file declaring more
memory-field entries than the documented ceiling, and a file declaring a single
`new_bytes` run longer than the documented per-run ceiling, each produce
**exactly one** `MF-ENTRY-LIMIT` issue per breach, **drop the offending entry**,
**keep the in-ceiling entries**, and **do not raise**. The verdict is
deterministic: the issue is present, the surviving change-set is non-empty and
holds exactly the in-ceiling entries.

**Export-time re-resolution (TC-036).** TC-036 covers LLR-007.5. With a
`make_patch_a2l` A2L loaded, it asserts a selective export re-resolves the
parameter `ChangeList` through the batch-03 `resolve_against_a2l` path
(verified via a spy / call assertion on that entry point) and feeds the
resulting `ResolutionResult` to the CDFX writer. With **no** A2L loaded, it
asserts the export still proceeds — producing an unresolved `ResolutionResult`,
collecting **exactly one** `ValidationIssue`, and **raising no exception** —
the `unresolved-no-a2l` collect-don't-abort mirror.

**Selective-export split (TC-028).** TC-028 builds a `UnifiedChangeSet` with a
non-empty parameter half and a non-empty memory-field half, requests a
selective export, and asserts **exactly two files** are produced — one `.cdfx`
under `.s19tool/workarea/`, one `.json` under `.s19tool/workarea/` — and that
they are **distinct files** (the two halves are never merged into one). TC-030
additionally asserts the `.cdfx` is produced through a call into the unchanged
batch-03 `write_cdfx_to_workarea` (verified via a spy / call assertion on the
batch-03 writer entry point) and that `s19_app/tui/cdfx/writer.py` is
byte-unchanged by this batch.

> **Security hand-off to Phase 2.** The unified change-set file and the
> memory-field JSON file are **parsed from outside the app** — the read path
> (LLR-006.x) is an external-input surface. JSON parsing via the stdlib `json`
> module is materially lower-risk than the batch-03 XML path: `json` has **no
> entity-expansion / DOCTYPE / external-entity attack surface**, so the
> billion-laughs / `SYSTEM`-entity test cases TC-027a/TC-027b of batch-03 have
> **no batch-04 equivalent** and are deliberately not carried over. The
> residual external-input concerns the Phase 2 security-reviewer should
> confirm are: **(1) path handling** — LLR-006.3 / TC-021 require every
> user-supplied input path to resolve through `workspace.resolve_input_path`
> (path resolution; reparse-point rejection is a *write*-side guarantee —
> LLR-005.4 / LLR-007.2 / TC-018 require every write to go through the
> `workspace.py` containment path); **(2) resource bounds** — LLR-006.4 /
> TC-022 require the 256 MB pre-parse on-disk size cap, and LLR-006.5 / TC-037
> require a decoded-structure ceiling (entry count and single-`new_bytes`-run
> length) enforced during reconstruction so a small sub-cap file cannot declare
> a multi-GB in-memory structure; **(3) nesting depth** — LLR-006.2 / TC-035
> require a deeply-nested JSON document to surface as an `MF-JSON-PARSE` issue
> with the reader catching the `RecursionError` (a `RuntimeError`, not a
> `json.JSONDecodeError`) rather than letting it escape. The recommendation is
> to **reuse the existing `workspace.py` containment guards verbatim**
> (constraint C-10) — no new path-handling code. The deeply-nested-JSON case,
> previously a Phase-2 review checkpoint, is now a normative clause
> (LLR-006.2) with its own TC (TC-035), and the decoded-structure ceiling is
> LLR-006.5 with TC-037 — both raised by the Phase 2 security-reviewer
> (S-001 / S-002) and folded into the requirement set in this iteration. These
> items are flagged for the Phase 2 security-reviewer; TC-018, TC-021, TC-022,
> TC-035 and TC-037 are the validation hooks.

### 5.6 Inspection checklist (LLR-004.2, LLR-009.2 → TC-027)

TC-027 is a static-review test case. Pass requires **all** of:

- [ ] `s19_app/tui/cdfx/changelist.py` and `s19_app/tui/cdfx/reader.py` are
      **byte-unchanged** by this batch (constraint C-3); the unified change-set
      container holds a `ChangeList` as a **member** (composition), not as a
      base class.
- [ ] `s19_app/tui/cdfx/writer.py` is **byte-unchanged** by this batch
      (constraint C-1) — confirmed jointly with TC-030.
- [ ] No JSON parse/serialize call and no memory-change / unified-change-set /
      export model logic appear in `app.py`; `app.py` holds only UI-state
      wiring that calls the service layer (constraint C-7, LLR-009.2).
- [ ] The memory-change model, the unified change-set container, the unified
      JSON read/write and the selective-export coordinator live in dedicated
      service-style modules inside `s19_app/tui/cdfx/` (or `tui/services/`),
      not in `app.py` (constraint C-7, §6.2.1 OQ-5).
- [ ] New public functions carry the `PROJECT_RULES.md` docstring section
      order (Summary→Args→Returns→Raises→Data Flow→Dependencies→Example) and
      type hints (constraint C-6) — spot-checked, not exhaustively.
- [ ] No new runtime dependency added to `pyproject.toml` (constraint C-4);
      `requirements.txt` unchanged — every file read/write uses stdlib `json`.

### 5.7 Test-case catalogue and traceability

> Every LLR maps to ≥1 TC; every HLR maps to its decomposed LLRs' TCs.
> "Method" abbreviations: U = test (unit), I = test (integration),
> RT = test (round-trip), INSP = inspection, A = analysis (used as a
> corroborating method only — see §5.1). A cell listing two methods
> carries a primary plus a corroborating method.

| TC | Title | Method | Covers LLR | Parent HLR | Expected result |
|----|-------|--------|------------|------------|-----------------|
| TC-001 | Memory-change entry construction | U | LLR-001.1 | HLR-001 | An entry built with an `address` and a byte run reports its fields; `new_bytes` preserves order and length; the entry exposes its addressed range as `(address, address+len(new_bytes))`. |
| TC-002 | Add / edit / remove and identity de-duplication | U | LLR-001.2, LLR-001.3 | HLR-001 | Add-then-remove of one address leaves the list empty; editing changes only the targeted entry's `new_bytes`; adding the same `address` twice yields one entry carrying the latest bytes. |
| TC-003 | Deterministic memory-change ordering | U | LLR-001.4 | HLR-001 | Two serializations of the same memory-change list produce identical entry order. |
| TC-004 | Memory-change list — HLR-001 model coherence | U | LLR-001.1, LLR-001.2 | HLR-001 | A list built, edited and queried through the model API reports a consistent entry set; this is the HLR-001 roll-up case. |
| TC-005 | Validate an entry against the loaded image ranges | U | LLR-002.1 | HLR-002 | Against a `make_ranged_s19` `LoadedFile`: an entry fully inside a range is `inside`; an entry crossing a range end is `partial`; an entry in the inter-range gap is `outside`; the `memory_change_factory` gap-spanning entry (run starts in range 1, crosses the gap, ends in range 2) receives the **single** status `partial`, not one status per touched range; the validator reads `LoadedFile.ranges`, no firmware re-parse. |
| TC-006 | Out-of-range / partial entries collect a warning, never abort | U | LLR-002.2 | HLR-002 | An `outside` entry produces exactly one warning `ValidationIssue` naming its address; a `partial` entry produces exactly one warning issue; the gap-spanning entry that touches two loaded ranges produces **exactly one** warning issue (not one per range); the memory-change list stays usable, no exception raised; no issue message echoes the entry's raw `new_bytes` content. |
| TC-007 | Validation without a loaded image | U | LLR-002.3 | HLR-002 | With no image loaded, every entry is marked `unvalidated-no-image`; the list is still buildable and listable; no exception. |
| TC-008 | Inter-entry overlap and malformed-`new_bytes` rejection | U | LLR-002.4, LLR-002.5 | HLR-002 | **Overlap arm (LLR-002.4):** the `memory_change_factory` overlap pair — distinct start addresses `0x100` and `0x104`, each `len 8`, with intersecting runs — each produce exactly one overlap warning `ValidationIssue`; the list stays usable, no exception raised. **`ValueError` arms (LLR-002.5):** constructing a memory-change entry with a byte value of `256` (greater than 255), with a negative byte value, or with an empty `new_bytes` run each raises `ValueError`. |
| TC-009 | Hex display of the stored bytes | U | LLR-003.1 | HLR-003 | Bytes `[0x01,0xAB,0xFF]` render as the string `01 AB FF` — two-digit uppercase, space-separated. |
| TC-010 | ASCII and decimal companion renderings | U | LLR-003.2 | HLR-003 | Bytes `[0x41,0x42]` render ASCII `AB` and decimal `65 66`; a byte outside 0x20–0x7E renders as the exact placeholder character `.` (the period, byte `0x2E`) pinned in LLR-003.2, keeping positional alignment with the hex form. |
| TC-011 | Display derivation does not mutate stored bytes | U | LLR-003.3 | HLR-003 | An entry's stored `new_bytes` is byte-identical before and after every hex / ASCII / decimal rendering call. |
| TC-012 | Unified change-set holds both halves | U | LLR-004.1 | HLR-004 | A `UnifiedChangeSet` exposes its parameter `ChangeList` and its `MemoryChangeList` as distinct attributes; each is independently accessible. |
| TC-013 | Independent mutation, per-half counts, empty-state | U | LLR-004.3, LLR-004.4, LLR-004.5 | HLR-004 | Adding a memory change leaves the parameter `ChangeList` unchanged and vice versa; an empty container reports counts `(0,0)` and reports empty; after two memory + one parameter change the counts are `(1,2)` and the container does not report empty. |
| TC-014 | Well-formed-but-wrong-shape JSON emits `MF-BAD-STRUCTURE` | U | LLR-006.2 | HLR-006, HLR-008 | Each `MF-BAD-STRUCTURE` variant of `make_rule_violation_unified_file` — a well-formed JSON document carrying no recognised parameter / memory-field halves (`[]`, `42`, `{"foo": 1}`) — produces exactly one error-level `MF-BAD-STRUCTURE` `ValidationIssue`, returns an **empty unified change-set**, and raises **no exception** — in particular **no `KeyError`** from indexing an absent half. |
| TC-015 | Unified file JSON structure | U | LLR-005.1 | HLR-005 | The written file is valid JSON re-parseable by `json.loads` and carries a format-identifier field, a version field, a parameter half and a memory-field half. |
| TC-016 | Unified file encodes each parameter entry | U | LLR-005.2 | HLR-005 | A parameter `ChangeList` entry round-trips its `parameter_name`, `array_index` (including the `None` scalar/string shape) and `value` through the unified file. |
| TC-017 | Unified file encodes each memory-field entry | U | LLR-005.3 | HLR-005 | A memory-change entry round-trips its exact integer `address` and its exact ordered `new_bytes` sequence through the unified file with no loss. |
| TC-018 | Unified file write is work-area-contained | U | LLR-005.4 | HLR-005 | A save produces a JSON file whose resolved path lies under `.s19tool/workarea/`; a write target that is, or whose traversed parents include, a symbolic link / NTFS reparse point is rejected with a write-side `ValidationIssue`, not a crash; a save onto an existing filename produces a dedup-suffixed file, never a silent clobber. **Reparse-point arm — deterministic mechanism:** the arm uses an **injectable reparse-point probe** (mirroring the §5.4 size-probe seam) the test stubs to report a reparse-point target, so the rejection path is exercised without the OS privilege to create a real symlink; where a real reparse point is used instead, the arm carries an explicit `skipif` / `xfail` with a **recorded reason** so a skip is visible in the report, never silent (reuses the batch-03 CV-03 approach). |
| TC-019 | Unified file reader parses both halves | U | LLR-006.1 | HLR-006 | `make_unified_file` parses to a unified change-set with a populated parameter `ChangeList` and a populated `MemoryChangeList`. |
| TC-020 | Unified file reader tolerates malformed JSON | U | LLR-006.2 | HLR-006, HLR-008 | A truncated / garbage JSON file → exactly one `MF-JSON-PARSE` error `ValidationIssue`, an empty unified change-set, no exception raised. |
| TC-021 | Unified file reader path resolution | U | LLR-006.3 | HLR-006 | A valid unified-file path is resolved through `workspace.resolve_input_path` and read; an unresolvable path yields exactly one error `ValidationIssue` and **no file is opened** (asserted via a no-open spy on the file-open seam). |
| TC-022 | Read-path size bound | U, A | LLR-006.4 | HLR-006, HLR-008 | Using `make_oversized_unified_file` and the **size-probe seam**: with the probe stubbed to report an over-256 MB byte size, the reader produces exactly one `MF-SIZE-CAP` issue, an empty unified change-set, and `json.load` is never reached — the size check precedes parsing. The 256 MB cap is the shared `DEFAULT_COPY_SIZE_CAP_BYTES` (`analysis`). |
| TC-023 | Memory-field structural rule violations emit `MF-*` issues | U | LLR-008.1 | HLR-008 | Each of `MF-NO-ADDRESS` (missing `address`), `MF-EMPTY-BYTES` (empty `new_bytes`) and `MF-BYTE-RANGE` (a byte value outside 0–255) is provoked by a crafted `make_rule_violation_unified_file` variant and asserted with its documented code and severity; the read does not abort, and the valid sibling entry each variant also carries is asserted to be recovered (collect-don't-abort). |
| TC-024 | Unknown file version is tolerated | U | LLR-008.2 | HLR-008 | A unified / memory-field file declaring an unrecognised version token reads its entries and produces exactly one info-level `MF-VERSION-UNKNOWN` `ValidationIssue`. |
| TC-025 | Unified-file round-trip — write then read recovers the change-set | RT | LLR-006.1 (+ HLR-005, HLR-006) | HLR-005, HLR-006 | A `UnifiedChangeSet` with a scalar + 1-D array + ASCII parameter half **including the three adversarial IEEE floats** and a memory-field half with `inside` + `partial` + `outside` + a multi-byte run is written to a unified JSON file then read back, and is **structurally equal**: same parameter `(parameter_name, array_index)` keys with values asserted by **exact `==`, no float tolerance**; same memory-field `address` keys with `new_bytes` recovered as the exact ordered byte sequence; same deterministic order in each half. **Equality predicate (pinned):** the validation / resolution-status fields are **excluded** from the equality assertion — they are **re-derived on read** (a freshly-read memory-field entry re-validates against the loaded image, a freshly-read parameter entry re-resolves against the loaded A2L) and are therefore asserted **separately** as a re-derivation check, not as part of the structural-equality predicate. Any write or read defect that drops, mis-shapes or value-loses an entry fails the structural assertion. See §5.5. |
| TC-026 | Unified change-set composes the two existing list types | U | LLR-004.1, LLR-004.2 | HLR-004 | The container's parameter half is an instance of the batch-03 `ChangeList` type held by composition (not a subclass); its memory half is a `MemoryChangeList`; mutating either through the container's accessors does not alter the other. (Runtime corroboration of the TC-027 inspection clause.) |
| TC-027 | Compose-not-subclass and `app.py`-clean inspection | INSP | LLR-004.2, LLR-009.2 | HLR-004, HLR-009 | The §5.6 inspection checklist passes in full — `changelist.py` / `reader.py` / `writer.py` byte-unchanged, the container composes a `ChangeList`, no model / JSON logic in `app.py`, handler logic in service-style modules, docstring/type-hint conventions held, no new dependency. |
| TC-028 | Selective export produces two distinct work-area files | U | LLR-007.3 | HLR-007 | A selective export of a unified change-set with both halves populated yields exactly two files — one `.cdfx` and one `.json` — each resolving under `.s19tool/workarea/`, distinct, never merged into one file. |
| TC-029 | Selective export produces the memory-field JSON file | U | LLR-007.2 | HLR-007 | The memory-field export file is valid JSON carrying a format identifier, a version and every memory-change entry's exact `address` and `new_bytes`; the file's **resolved path lies under `.s19tool/workarea/`** (the LLR-007.2 write-path containment clause); a reparse-point write target for the memory-field file is rejected with a `ValidationIssue`, not a crash. |
| TC-030 | Selective export reuses the unchanged batch-03 CDFX writer | U | LLR-007.1 | HLR-007 | The exported `.cdfx` is produced by a call into the batch-03 `write_cdfx_to_workarea` (asserted via a spy / call assertion on that entry point); `s19_app/tui/cdfx/writer.py` is byte-unchanged by this batch. |
| TC-031 | Selective export collects and reports each half's issues | U | LLR-007.4 | HLR-007, HLR-008 | A selective export of a unified change-set whose parameter half has one excluded (unresolved) entry **still** produces the memory-field JSON file, and the combined result reports the parameter-half exclusion warning tagged with its originating half — neither half aborts because the other produced issues. |
| TC-032 | Patch Editor renders the memory-change list | I | LLR-009.1 | HLR-009 | Under `App.run_test()`, adding a memory change adds a visible memory-change row showing the address, the hex rendering and the validation status; the batch-03 parameter-change rows remain visible and unchanged. |
| TC-033 | Patch Editor memory-change controls are wired | I | LLR-009.2 | HLR-009 | Under `App.run_test()`, submitting the address and new-bytes inputs mutates the memory-change list and re-renders the rows; add / edit / remove each update the rendered rows through the service layer. |
| TC-034 | Patch Editor save / load / selective-export actions | I | LLR-009.3 | HLR-009 | Under `App.run_test()`: the save action produces a unified change-set file under `.s19tool/workarea/` and surfaces issues via the status path; the load action populates both halves from a valid unified file and surfaces read issues — a malformed file surfaces issues without crashing the screen; the selective-export action produces the `.cdfx` and the memory-field JSON file and reports issues. |
| TC-035 | Deeply-nested JSON does not escape as `RecursionError` | U | LLR-006.2 | HLR-006, HLR-008 | `make_deeply_nested_unified_file` (a small file, a few hundred KB, nested deep enough to overflow the stdlib `json` parser) fed to the unified reader produces exactly one `MF-JSON-PARSE` error `ValidationIssue`, returns an empty unified change-set, and **no `RecursionError` escapes** — the reader's exception handling catches `RecursionError` (a `RuntimeError`), not only `json.JSONDecodeError`. |
| TC-036 | Selective export re-resolves the parameter half | U | LLR-007.5 | HLR-007 | **A2L-loaded arm:** with a `make_patch_a2l` A2L loaded, a selective export re-resolves the parameter `ChangeList` through the batch-03 `resolve_against_a2l` path (asserted via a spy / call assertion on that entry point) and feeds the resulting `ResolutionResult` to the CDFX writer. **No-A2L arm:** with no A2L loaded, the export produces an unresolved `ResolutionResult`, collects exactly one `ValidationIssue`, and raises no exception. |
| TC-037 | Read-path decoded-structure ceiling emits `MF-ENTRY-LIMIT` | U | LLR-006.5 | HLR-006, HLR-008 | Using `make_over_ceiling_unified_file`: a unified file declaring more memory-field entries than the documented LLR-006.5 ceiling produces one `MF-ENTRY-LIMIT` issue and a non-empty change-set holding exactly the in-ceiling entries; a unified file declaring a single `new_bytes` run longer than the documented per-run ceiling produces one `MF-ENTRY-LIMIT` issue, drops that entry, keeps the rest; neither raises an exception. |

**Reverse traceability check.** Every LLR-001.1 … LLR-009.3 (**37 LLRs** — the
§4 tally 4 (LLR-001.x) + 5 (LLR-002.x) + 3 (LLR-003.x) + 5 (LLR-004.x) +
4 (LLR-005.x) + 5 (LLR-006.x) + 5 (LLR-007.x) + 3 (LLR-008.x) +
3 (LLR-009.x) = 37) appears in the "Covers LLR" column of §5.3 and the
catalogue above. Every HLR-001 … HLR-009 (9 HLRs) maps to the TCs of its
decomposed LLRs. The catalogue holds **37 active test cases over 37 IDs
(TC-001 … TC-037)** — there is no longer any reserved/unallocated slot. TC-014,
previously a reserved slot, is in this iteration **allocated to the
`MF-BAD-STRUCTURE` well-formed-but-wrong-shape case** (Q-07); the three new
LLRs of this iteration — LLR-002.5 (malformed `new_bytes`), LLR-006.5
(decoded-structure ceiling) and LLR-007.5 (export-time re-resolution) — are
covered by TC-008 (`ValueError` arms), TC-037 and TC-036 respectively, with
TC-035 added for the LLR-006.2 deeply-nested-JSON clause. No requirement is
left without a TC; no TC is orphaned.

> **Catalogue-size reconciliation.** Filling TC-014 and adding TC-035 / TC-036 /
> TC-037 in this iteration **changes the catalogue size**: it is now
> **37 active test cases over 37 IDs (TC-001 … TC-037), no reserved/unallocated
> slot** — superseding the earlier "33 active test cases over 34 IDs
> (TC-001…TC-034); TC-014 reserved" wording. Section 5 (§5.2, §5.7, §5.9) uses
> the new count uniformly. The §1.5 document-overview line and the §3 preamble
> still carry the **superseded** "33 active / 34 IDs / TC-014 reserved"
> phrasing; those two non-Section-5 lines are flagged here for the architect to
> bring into line with this catalogue during the iteration-2 closure pass — the
> authoritative count is the §5.7 figure above.

> **Per-LLR ↔ TC cross-check (37 LLRs).** LLR-001.1 → TC-001, TC-004;
> LLR-001.2 → TC-002, TC-004; LLR-001.3 → TC-002; LLR-001.4 → TC-003;
> LLR-002.1 → TC-005; LLR-002.2 → TC-006; LLR-002.3 → TC-007;
> LLR-002.4 → TC-008 (overlap arm); LLR-002.5 → TC-008 (`ValueError` arms);
> LLR-003.1 → TC-009; LLR-003.2 → TC-010; LLR-003.3 → TC-011;
> LLR-004.1 → TC-012, TC-026; LLR-004.2 → TC-027, TC-026;
> LLR-004.3 → TC-013; LLR-004.4 → TC-013; LLR-004.5 → TC-013;
> LLR-005.1 → TC-015; LLR-005.2 → TC-016; LLR-005.3 → TC-017;
> LLR-005.4 → TC-018; LLR-006.1 → TC-019, TC-025;
> LLR-006.2 → TC-020, TC-014, TC-035; LLR-006.3 → TC-021;
> LLR-006.4 → TC-022; LLR-006.5 → TC-037; LLR-007.1 → TC-028, TC-030;
> LLR-007.2 → TC-029; LLR-007.3 → TC-028; LLR-007.4 → TC-031;
> LLR-007.5 → TC-036; LLR-008.1 → TC-023; LLR-008.2 → TC-024;
> LLR-008.3 → TC-022; LLR-009.1 → TC-032; LLR-009.2 → TC-033, TC-027;
> LLR-009.3 → TC-034. All 37 LLRs carry ≥1 TC; all 9 HLRs are covered through
> their LLRs (§5.2).

### 5.8 Testability assessment and open questions

**Weakly-testable requirements** (objectively verifiable, but with a stated
caveat):

- **LLR-004.2 — compose-not-subclass.** Verified primarily by *inspection*
  (TC-027) — "`changelist.py` byte-unchanged" and "held by composition" are
  static facts, not runtime assertions. TC-026 adds a runtime corroboration
  (an `isinstance` / non-subclass check plus an independent-mutation check),
  so the verdict is not purely reviewer-subjective, but the byte-unchanged
  clause remains a static review. The §5.6 checklist makes the inspection
  verdict objective.
- **LLR-007.1 — "reuses the unchanged batch-03 writer".** TC-030 asserts the
  `.cdfx` is produced *through a call into* `write_cdfx_to_workarea` (a spy on
  the entry point) and that `writer.py` is byte-unchanged. The "byte-unchanged"
  half is a static fact (git diff / file-hash check), confirmed jointly by the
  §5.6 checklist; the "produced via the writer" half is a genuine runtime
  assertion. This is a stated caveat, not a gap.
- **LLR-009.2 — `app.py` holds no model/JSON logic.** The mutation half is an
  integration assertion (TC-033); the "no JSON parse/serialize or model logic
  in `app.py`" clause is verified by *inspection* (TC-027, §5.6). A static
  review, not a runtime test — same status as the batch-03 LLR-007.5.
- **HLR-003 / HLR-009 — demo corroboration.** The `demo` method for these two
  is corroboration only; the pass/fail gate is the `test`-method TCs. The demo
  has no objective threshold and is not counted toward coverage.
- **`MF-*` rule-code spelling.** HLR-008 requires "a fixed, documented set of
  structural validation rules … one `ValidationIssue` with a stable code per
  rule violation" but does not pin the code strings. The TCs assert on the
  documented codes — the `MF-*` set proposed in §5.4 is a recommendation. The
  testability requirement is that Phase 3 **pins and documents** the code set
  before the TCs are written; an undocumented or unstable code set would make
  TC-014 / TC-020 / TC-022 / TC-023 / TC-024 / TC-035 / TC-037
  non-deterministic. Flagged for Phase 2 to confirm the rule-code set is fixed
  and documented (this is the batch-04 analogue of the batch-03 `W-*` / `R-*`
  discipline).

All other HLRs/LLRs are objectively testable with the synthetic fixtures of
§5.4. No requirement was found *un*-testable.

**Open questions raised by this validation pass — all resolved in
Phase 1 iteration 2:**

- **OQ-V1 — memory-change entry identity vs. on-disk key shape — RESOLVED.**
  The iteration-2 architect pass resolved this normatively in LLR-005.3: the
  memory-field half of the unified file is a **JSON array of objects**, each
  object carrying `address` as an **integer-valued field** (a JSON number),
  never as a JSON object key. The in-app `MemoryChangeList` still keys entries
  by `address` (LLR-001.3) — that is the in-memory shape; the on-disk shape is
  now pinned. TC-017 and TC-025 assert the array-of-objects shape and the exact
  integer round-trip. No open item remains.
- **OQ-V2 — `partial` overlap with multiple ranges — RESOLVED.** The
  iteration-2 architect pass resolved this in LLR-002.1: an entry whose
  addressed byte range touches **more than one** loaded range (spanning a gap)
  receives the **single status `partial`** and produces **exactly one**
  `ValidationIssue` — one entry, one status, one issue. TC-005 (status) and
  TC-006 (single-issue) now cover the gap-spanning case explicitly against the
  `memory_change_factory` gap-spanning variant. No open item remains.
- **OQ-V3 — deeply-nested JSON recursion — RESOLVED.** The iteration-2 pass
  promoted this to a normative clause in LLR-006.2: a deep-nesting parse
  failure is treated as **one `MF-JSON-PARSE` issue**, returns an empty unified
  change-set, and does not raise — the reader's exception handling catches
  `RecursionError` (a `RuntimeError`), not only `json.JSONDecodeError`. It is
  no longer a deferred review checkpoint: TC-035, backed by the
  `make_deeply_nested_unified_file` fixture, is its dedicated test case. No
  open item remains.

**Items to pin in Phase 3** (carried into the increment plan, not open
questions — each has a recommended value, Phase 3 records the final choice):

- The concrete `MF-*` rule-code spellings — `MF-JSON-PARSE`,
  **`MF-BAD-STRUCTURE`** (well-formed-but-wrong-shape, LLR-006.2),
  `MF-NO-ADDRESS`, `MF-EMPTY-BYTES`, `MF-BYTE-RANGE`, `MF-VERSION-UNKNOWN`,
  `MF-SIZE-CAP`, **`MF-ENTRY-LIMIT`** (decoded-structure ceiling, LLR-006.5),
  `MF-PATH-UNRESOLVED` — fixed and documented before the TCs are written.
- The non-printable-byte ASCII placeholder character — recommended **`.`**
  (the period character, byte `0x2E`, the conventional hex-dump placeholder),
  pinned in LLR-003.2 and asserted by TC-010 on that exact character.
- The two numeric ceilings of LLR-006.5 — the memory-field **entry-count**
  ceiling and the single-`new_bytes`-**run-length** ceiling — documented as
  named constants the reader enforces and `make_over_ceiling_unified_file`
  reads.

### 5.9 Batch acceptance criteria

The batch is accepted for Phase 4 sign-off when **all** of the following hold:

1. **Coverage** — 100% of the 9 HLRs and 37 LLRs map to at least one TC with a
   recorded **pass** result; the §5.7 catalogue of **37 active test cases over
   37 IDs (TC-001 … TC-037)** is the coverage record — there is no
   reserved/unallocated slot.
2. **Method assigned** — no HLR or LLR is left without a validation method
   (§5.2 / §5.3 are complete).
3. **No blocker fails** — zero failing TCs at error/blocker severity. A
   warning-level finding may be accepted with a written justification.
4. **Round-trip pass** — TC-025 passes: a parameter half (scalar + 1-D array +
   ASCII + the three adversarial IEEE floats) plus a memory-field half
   (`inside` + `partial` + `outside` + a multi-byte run) survives a write→read
   cycle structurally equal, with exact float `==` on parameter values and the
   exact ordered byte sequence on every memory-field entry.
5. **Rule-code completeness** — every `MF-*` structural rule code is provoked
   by a TC and emitted with the documented code and severity (TC-014, TC-020,
   TC-022, TC-023, TC-024, TC-035, TC-037); Phase 2 has confirmed the rule-code
   set is fixed and documented (HLR-008).
6. **Collect-don't-abort honored** — every read-error TC (TC-014, TC-020,
   TC-022, TC-023, TC-035, TC-037) and the malformed-load arm of TC-034 confirm
   the reader returns issues without raising an uncaught exception — including
   no escaping `KeyError` (TC-014) and no escaping `RecursionError` (TC-035) —
   and TC-006 / TC-007 confirm the same for the memory-change validator.
7. **Selective-export split** — TC-028 confirms a selective export yields
   exactly two distinct work-area files; TC-030 confirms the `.cdfx` is
   produced through the unchanged batch-03 writer; TC-036 confirms the
   export-time re-resolution of the parameter half (A2L-loaded and no-A2L
   arms); TC-031 confirms the two halves export independently with cross-half
   issue reporting.
8. **Containment and resource bounds** — TC-018 confirms unified-file writes
   are work-area-contained, TC-029 confirms the memory-field export file
   resolves under `.s19tool/workarea/`, TC-021 confirms load-path resolution
   through `resolve_input_path`, TC-022 confirms the 256 MB read-path on-disk
   size cap, TC-037 confirms the LLR-006.5 decoded-structure ceiling, TC-035
   confirms the deeply-nested-JSON `RecursionError` catch; the Phase 2
   security-reviewer has reviewed the path-handling and resource-bound surface
   (§5.5 hand-off) and signed off.
9. **No new dependency** — TC-027's §5.6 checklist confirms `pyproject.toml` /
   `requirements.txt` are unchanged (constraint C-4) and `changelist.py`,
   `reader.py`, `writer.py` are byte-unchanged (constraints C-1, C-3).
10. **Synthetic fixtures only** — every firmware-image / `.cdfx` / unified-file
    / memory-field-file / change-list fixture is synthetic, generated in-test
    or via the §5.4 `conftest.py`-style generators (constraint C-9).

---

## 6. Appendices

### 6.1 Extended glossary

See §1.3. Two distinctions are load-bearing for this batch:

- **Parameter change vs. memory-field change.** A parameter change (batch-03)
  is keyed by an A2L `(parameter_name, array_index)` and carries a *physical*
  value resolved through an A2L type. A memory-field change (batch-04) is keyed
  by a raw memory `address` and carries a run of *raw bytes* with no type
  resolution. The two are different kinds; the unified change-set holds both
  without merging them.
- **Unified change-set file vs. CDFX file.** The unified file (JSON) is the
  *working-document* format — it holds both halves and is what save/load
  round-trips. CDFX (`.cdfx`, XML) is an *export / hand-off* format — produced
  by selective export from the parameter half only, for vCDM.

### 6.2 Relevant design decisions

- **DD-1 — Unified file and memory-field file are JSON via stdlib `json`.**
  The owner said "JSON or something convenient" and asked for a recommendation;
  stdlib `json` is recommended and adopted — it satisfies the
  no-new-dependency constraint C-4, is human-inspectable, and is the natural
  fit for the address/bytes/parameter records this batch serializes.
- **DD-2 — Memory-change value: stored as raw bytes, displayed hex-primary.**
  Each entry stores a raw byte run; hex (uppercase, two-digit, space-separated)
  is the primary display form, with ASCII and decimal as derived companion
  views (HLR-003). Hex is the natural form for raw memory; the companions are
  display-only and never mutate the stored bytes.
- **DD-3 — Memory-change entry addresses a contiguous byte range.** One entry =
  one start address + a contiguous run of new bytes. A non-contiguous edit set
  is several entries. This keeps the model simple and maps cleanly to the
  loaded image's contiguous-range structure.
- **DD-4 — Reuse the batch-03 CDFX writer unchanged for the parameter export.**
  Constraint C-1 — selective export of the parameter half calls
  `write_cdfx_to_workarea`; no CDFX code is re-implemented or modified.
- **DD-5 — Compose, do not subclass, the batch-03 `ChangeList`.** The unified
  change-set holds a `ChangeList` as a member (LLR-004.2); `changelist.py` and
  `reader.py` are byte-unchanged (constraint C-3).
- **DD-6 — Validate memory changes against the loaded image, collect-don't-
  abort.** The validator reads `LoadedFile.ranges` / `S19File.get_memory_ranges`
  read-only and records `inside` / `partial` / `outside` / `unvalidated-no-
  image` status plus `ValidationIssue` warnings — mirroring the batch-03
  `ResolutionStatus` / `ValidationIssue` pattern.
- **DD-7 — All findings are `ValidationIssue`.** No new issue model; severities
  round-trip through `color_policy` (constraint C-5).
- **DD-8 — Work-area containment reused.** Every file this batch writes goes
  through the `workspace.py` containment path; every input path is resolved
  through `resolve_input_path` (constraint C-10).
- **DD-9 — Applying changes to the firmware image is deferred.** The
  memory-change model is a recorded *intent*; `S19File.set_bytes_at` /
  `set_string_at` are not called, and no modified S19/HEX is exported. This is
  the explicit out-of-scope boundary (§1.2).
- **DD-10 — Memory-field on-disk encoding is pinned: a JSON array of objects.**
  The memory-field half of the unified file and of the memory-field export file
  is a JSON **array of objects**, each object carrying `address` as an
  integer-valued field (a JSON number) and `new_bytes` as a JSON array of
  integers; `address` is never a JSON object key. JSON object keys are always
  strings — encoding `address` as a key would force a hex-vs-decimal re-parse
  ambiguity between writer and reader. The in-app `MemoryChangeList` still keys
  entries by `address` (LLR-001.3); DD-10 pins only the *on-disk* shape. This
  resolves the §5.8 open question OQ-V1 normatively and is baked into LLR-005.3
  and LLR-007.2.
- **DD-11 — Selective export re-resolves the parameter half at export time.**
  The batch-03 CDFX writer (`write_cdfx_to_workarea`) requires a mandatory
  typed `ResolutionResult`; the unified change-set and the unified file carry
  the parameter half as a plain `ChangeList` only (no resolution state). The
  selective-export coordinator therefore re-resolves the parameter `ChangeList`
  against the loaded A2L immediately before the CDFX write, via the batch-03
  `resolve_against_a2l` path (mirroring `cdfx_service`), and feeds the writer
  the resulting `ResolutionResult`. The batch-03 writer stays literally
  unchanged (constraint C-1) and the unified file stays resolution-free
  (LLR-005.2). Re-resolution is a transient export-time computation, never
  persisted. Baked into LLR-007.1 and LLR-007.5; widens assumption A-7.

#### 6.2.1 Decisions taken in the owner's absence

The owner is away; each genuine open question below was resolved with a
best-criteria default, baked into the requirements, and recorded here so the
owner can override later.

| ID | Open question | Default taken | Where baked in | Reversible? |
|----|----------------|---------------|----------------|-------------|
| OQ-1 | What does a memory-change entry address — a single byte, or a range? | A **contiguous byte range**: one start `address` + a non-empty ordered run of new bytes. A non-contiguous edit set is modelled as several entries. | A-4, DD-3, LLR-001.1 | Yes — widening to non-contiguous runs is additive. |
| OQ-2 | What form is the memory value entered and displayed in? | Stored as **raw bytes**; displayed **hex-primary** (uppercase two-digit, space-separated) with **ASCII and decimal companion** views derived for display only. | A-5, DD-2, HLR-003, LLR-003.x | Yes — adding more display forms is additive. |
| OQ-3 | What format is the unified change-set file and the memory-field export file? | **JSON via the stdlib `json` module**, with a format-identifier + version header. The unified file carries the parameter half as plain JSON `ChangeListEntry` fields (not CDFX); CDFX remains the *export-only* format for the parameter half. | DD-1, A-7, HLR-005, LLR-005.1/005.2 | Yes — a format-id + version header is exactly what makes a future format change tolerable (LLR-008.2). |
| OQ-4 | How are memory changes that fall outside the loaded image handled? | **Validated, flagged, recorded** — status `outside` / `partial` plus a warning `ValidationIssue`; the entry is **not** dropped and **not** applied (apply is deferred, DD-9). With no image loaded the status is `unvalidated-no-image`. | A-2, HLR-002, LLR-002.1/002.2/002.3 | Yes — applying or rejecting out-of-range edits is a later policy choice. |
| OQ-5 | Where does the memory-change model and the unified change-set live? | Inside the **`s19_app/tui/cdfx/` package** (new modules — for example `memory.py`, `changeset.py`, `unified_io.py`, `export.py`) plus `cdfx_service` extension, mirroring the batch-03 package layout. No new top-level convention. | C-7, §2.1 | Yes — module placement is an internal decision. |
| OQ-6 | Is the in-app unified change-set one new class, or a tuple of the two existing lists? | One **new container class** (for example `UnifiedChangeSet`) composing a `ChangeList` and a `MemoryChangeList` — it gives a stable surface for per-half counts (LLR-004.4), the empty-state query (LLR-004.5), save/load and selective export. | HLR-004, LLR-004.1 | Yes — internal class shape. |
| OQ-7 | Does selective export reuse the batch-03 `write_cdfx_to_workarea`, or `write_cdfx` plus a custom placement? | Reuse **`write_cdfx_to_workarea`** — it already does the work-area containment placement (batch-03 LLR-007.7); no new write path. | C-1, C-10, DD-4, LLR-007.1 | Yes — but reversing it would re-introduce a write path the owner asked to avoid. |
| OQ-8 | Should overlapping memory-change entries be merged, rejected, or flagged? | **Flagged** with a warning `ValidationIssue` (LLR-002.4); never merged (would invent a combined edit) and never rejected (the engineer may still intend both). Consistent with the batch-03 `W-ARRAY-SPARSE` fail-loud, no-silent-fix culture. | LLR-002.4, OQ-4 | Yes — a merge or reject policy can be added later. |

### 6.3 Open risks

| ID | Risk | Mitigation / note |
|----|------|-------------------|
| RK-1 | **Apply-to-image expectation drift.** The owner may expect the memory changes to actually patch the loaded image; this batch only *records* them (DD-9). | Scoped out explicitly in §1.2 and DD-9; the deferral is stated in every relevant LLR. Surface to the owner at the Phase-2 gate. |
| RK-2 | **Batch-03 dependency.** Batch-04 reuses the batch-03 `cdfx/` package and `CdfxService`; if batch-03 is not merged/green at batch-04 start, the reuse (C-1, A-1) is blocked. | **Dependency flag — see the summary.** Confirm the batch-03 deliverable is merged and the suite is green before Phase 3. |
| RK-3 | **Unified file format coupling.** The unified file embeds the parameter `ChangeList` field shape (LLR-005.2); a future change to `ChangeListEntry` would change the unified file format. | The format-id + version header (LLR-005.1, LLR-008.2) makes a format revision detectable and tolerable; the unified writer/reader is the single point that knows the embedded shape. |
| RK-4 | **`S19File` vs `IntelHexFile` range API parity.** The validator consumes the loaded-image ranges; `S19File` exposes `get_memory_ranges`, and the TUI surfaces ranges via `LoadedFile.ranges`. The validator must read the `LoadedFile` snapshot, not branch on file type. | LLR-002.x is written against the `LoadedFile.ranges` / `mem_map` snapshot surface (A-3), which both loaders populate — no file-type branching. |
| RK-5 | **Patch Editor screen growth.** HLR-009 extends an already-functional batch-03 screen; the extension must not regress the parameter-change controls. | LLR-009.1 explicitly requires the batch-03 rows/controls to survive; the integration tests must assert both kinds coexist. Flag for `qa-reviewer` in the validation strategy. |
| RK-6 | **No client-format sample for the unified file.** The unified-file JSON shape is defined by this batch with no external standard to conform to. | This is acceptable — the unified file is an internal working-document format (§6.1), not an interop format; only the CDFX export half must conform to an external standard, and that reuses the unchanged batch-03 writer. |
