# Requirements Document — s19_app — Batch 2026-05-21-batch-03

> **Strict normative convention — IEEE 830 + EARS**
> - `shall` = normative, binding, verifiable requirement. **Only** inside HLR / LLR statements.
> - `should` = informative / explanatory text, **NOT binding**. **Only** outside HLR / LLR statements (rationale, description, context).
> - Any use of `should` inside an HLR / LLR statement is a **writing error** and will be flagged as a blocker in phase 2.
> - `may` = optional. `will` = future declaration or fact about an external actor.

---

## 1. Introduction

### 1.1 Purpose

This document specifies the requirements for **batch-03** of `s19_app`: making
the **Patch Editor** rail screen functional. Batch-02 delivered the Patch
Editor as an inert view shell (`R-TUI-027`, `PatchEditorPanel`); batch-03
replaces that shell with a working tool that lets a calibration engineer
**build a parameter change-list** and **exchange it as an ASAM CDFX
(`.cdfx`) calibration-data file** compatible with Vector vCDM.

Unlike batch-02 (a view-layer-only restyle), this batch **deliberately adds a
data-processing layer**: a change-list model and a CDFX format handler. That
expansion is approved and expected.

### 1.2 Scope

**In scope:**
- A **parameter change-list model** — entries keyed to A2L
  characteristic/parameter **name** + **array index** (e.g. `PARAMETER[0] : 23`).
- **Parameter resolution** of a change-list entry against the loaded A2L
  (reusing `s19_app/tui/a2l.py`).
- **Value entry and display** in the form best suited to the A2L data type
  (decimal / hex / signed decimal / float / ASCII string).
- **CDFX write** — serialize the change-list to a structurally valid CDF 2.0
  `.cdfx` file.
- **CDFX read** — parse and validate a `.cdfx` file, surfacing issues via the
  existing `ValidationIssue` collect-don't-abort pattern.
- **Patch Editor UI** — making `PatchEditorPanel` functional to build, edit,
  save and load the change-list.

**Out of scope (explicitly deferred — user-confirmed):**
- Applying the change-list to the firmware image / memory map.
- Exporting a modified S19 / Intel HEX file.
- Undo / redo history of edits.
- XSD schema-level validation — a deferred non-goal; validation is
  structural-only this batch (see §2.4 C-3 and §6.3 OQ-1/OQ-4).
- Multi-dimensional parameters (`MAP`, shared axes), structured/union types,
  and arrays-of-parameters (`*_ARRAY`). These are **read-tolerated** (parsed,
  surfaced as issues, shown read-only) but **not editable / not writable** this
  batch.
- vCDM round-trip verification with a live vCDM installation (no license / no
  sample available — residual risk, see §6.3).

### 1.3 Definitions, acronyms, abbreviations

| Term | Definition |
|------|------------|
| A2L | ASAM MCD-2 MC file describing ECU parameters (address, type, conversion). Already parsed by `s19_app/tui/a2l.py`. |
| ASAM | Association for Standardization of Automation and Measuring Systems. |
| CDF | ASAM MCD-2 CDF — Calibration Data Format; stores ECU parameter values. |
| CDFX | The XML serialization of CDF; file extension `.cdfx`. |
| CDF 2.0 | The targeted CDF version; `MSRSW/CATEGORY` token `CDF20`. |
| Change-list | The set of parameter changes the engineer builds in the Patch Editor; each entry = (parameter name, array index, value). |
| Characteristic | An A2L `CHARACTERISTIC` (calibratable parameter). |
| `MSRSW` | Root XML element of a CDFX file. |
| `SW-INSTANCE` | CDFX element representing one parameter; identified by `SHORT-NAME`. |
| `SW-VALUE-CONT` / `SW-VALUES-PHYS` | CDFX value container / physical-values element. |
| `V` / `VT` | CDFX numeric value element / text value element. |
| `VG` | CDFX value group — nests `V`/`VT` for arrays/tables. |
| Physical value | A converted, human-meaningful value (vs. raw implementation bytes). CDF stores physical values. |
| vCDM | Vector Calibration Data Management — the target consumer of the `.cdfx` files. |
| `ValidationIssue` | The project's structured finding record (`s19_app/validation/model.py`). |
| Patch Editor | The Direction B rail screen (item 6) this batch makes functional. |

### 1.4 References

- `.dev-flow/2026-05-21-batch-03/design-input/cdfx-research.md` — **CDFX format
  research summary; source-of-truth for the CDFX structure and validation
  rules referenced below.**
- `REQUIREMENTS.md` — `R-TUI-021` (rail), `R-TUI-027` (the inert Patch Editor
  shell this batch supersedes), `R-A2L-001`..`R-A2L-007` (A2L parsing reused).
- `.dev-flow/2026-05-20-batch-02/01-requirements.md` — batch-02 LLR/TC set.
- `CLAUDE.md`, `PROJECT_RULES.md` — project architecture and documentation
  conventions.
- ASAM CDF Wiki — https://www.asam.net/standards/detail/cdf/wiki/
- Requirements template — `~/.claude/templates/dev-flow/req-template-en.md`.

### 1.5 Document overview

Section 2 gives the overall description, constraints, assumptions and source
user stories. Section 3 lists high-level requirements (HLR), each tracing to a
user story. Section 4 decomposes each HLR into low-level requirements (LLR).
Section 5 holds the qa-reviewer validation strategy. Section 6 holds appendices
(glossary, design decisions, open risks).

**Authoritative requirement counts (Phase 3 amendment — array-coalescing
requirements gap):** this document specifies **7 user stories (US)**,
**8 high-level requirements (HLR)** and **44 low-level requirements (LLR)**.
The LLR total by HLR group is:
4 (LLR-001.x) + 4 (LLR-002.x) + 3 (LLR-003.x) + 9 (LLR-004.x) +
6 (LLR-005.x) + 8 (LLR-006.x) + 7 (LLR-007.x) + 3 (LLR-008.x) = **44**.
This 44-LLR total is authoritative and supersedes the "34" / "39" / "42 LLRs"
figures used in earlier drafts. Iteration 3 added three LLRs — **LLR-005.5**
(CDFX load-path resolution), **LLR-006.8** (read-path size / nesting-depth
bound) and **LLR-007.7** (work-area-contained CDFX write target) — to the
39-LLR set carried out of iteration 2. The Phase-3 amendment added two further
LLRs — **LLR-004.9** (writer coalesces array-element entries into one
`VAL_BLK` `SW-INSTANCE`; normative sparse-array rule) and **LLR-005.6** (reader
expands a `VAL_BLK` instance back into array-element entries) — to resolve the
Phase-3 array-coalescing requirements gap: the change-list keys entries by
`(parameter_name, array_index)`, so without coalescing the writer emitted one
same-`SHORT-NAME` `SW-INSTANCE` per array element, which is not standard ASAM
CDF 2.0. The amendment also made `array_index` `Optional[int]` (LLR-001.1).

---

## 2. Overall description

### 2.1 Product perspective

`s19_app` is a Python TUI/CLI for inspecting S19/Intel-HEX firmware images
cross-referenced with A2L and MAC artifacts. Its architecture has three layers:
**parsers → range/validation engine → TUI services + view code**
(`CLAUDE.md`).

Batch-03 adds a fourth concern that sits beside the parsers: a **CDFX format
handler** (read + write) and a **change-list model**. The Patch Editor screen
becomes a consumer of both, plus a consumer of the existing A2L parser for
parameter resolution and of the `ValidationIssue` model for surfacing CDFX
problems. No firmware image is modified; the CDFX file is an independent
artifact exchanged with vCDM.

The batch reuses, without re-implementing: A2L parsing (`tui/a2l.py`), the
`ValidationIssue` / `ValidationSeverity` model (`validation/model.py`), the
severity-to-colour policy (`tui/color_policy.py`), and the workspace path
helpers (`tui/workspace.py`).

### 2.2 Product functions

- F1 — Build a parameter change-list: add, edit and remove entries keyed to an
  A2L parameter name and array index.
- F2 — Resolve each change-list entry against the loaded A2L to obtain the
  parameter's data type, element count and category.
- F3 — Enter a value and display it in the form best suited to the resolved
  A2L data type (decimal, hex, signed decimal, float, ASCII string).
- F4 — Write the change-list to a structurally valid CDF 2.0 `.cdfx` file.
- F5 — Read a `.cdfx` file back into a change-list, validating it and
  collecting issues without aborting.
- F6 — Operate all of the above from a functional Patch Editor rail screen.

### 2.3 User characteristics

The primary user is a **calibration engineer**: an automotive/embedded
professional fluent in A2L parameters and CDF/CDFX exchange, who uses vCDM as
their calibration data management tool. They run `s19_app` to inspect a
firmware image and need to produce a parameter change-list as a `.cdfx` for
hand-off to vCDM, and to load `.cdfx` files produced elsewhere. They are
comfortable with a keyboard-driven TUI and expect, per the project's culture,
that malformed inputs are reported as issues rather than crashing the tool.

### 2.4 Constraints

| ID | Constraint |
|----|------------|
| C-1 | A2L parsing **shall not be re-implemented**; parameter resolution reuses `s19_app/tui/a2l.py`. Resolution **shall** run through the **enriched** A2L pipeline — `parse_a2l_file` → `extract_a2l_tags` → `enrich_a2l_tags_with_values` — not bare `extract_a2l_tags`, because the decode-relevant fields are populated only after enrichment. The named reuse surface is: the parsed payload (`record_layouts_by_name`, `compu_methods_by_name`), `enrich_a2l_tags_with_values`, the enriched tag fields `name`, `datatype`, `decode_type`, `element_count`, `char_type`, `address`, `length`, `section`, `record_layout_name`, and `DATATYPE_SIZES`. A bare `extract_a2l_tags` tag has `datatype = None` for a `CHARACTERISTIC`; resolution must therefore use the enriched object. |
| C-2 | CDFX read/write **shall use the Python standard library** (`xml.etree.ElementTree`) — **no new runtime dependency** (resolution of OQ-1/OQ-4). The runtime dependency set (`rich`, `textual`) is unchanged. |
| C-3 | CDFX validation this batch is **structural-only** and **shall** be implemented with the stdlib `xml.etree.ElementTree` (resolution of OQ-1/OQ-4). A `.cdfx` is "valid" exactly when it passes the documented `W-*` (write) / `R-*` (read) structural rule set of `design-input/cdfx-research.md` §7 (well-formedness + element/category/value rules) — there is no other validity oracle. **True ASAM-XSD schema conformance is an explicitly deferred non-goal** for this batch: it would require a new dependency (`lxml`/`xmlschema`) plus the licensed, non-redistributable ASAM CDF XSD, and is out of scope. |
| C-4 | New/changed code **shall follow `PROJECT_RULES.md`**: docstring section order (Summary→Args→Returns→Raises→Data Flow→Dependencies→Example), mandatory type hints, function granularity (~40-60 line split trigger). |
| C-5 | CDFX issue reporting **shall reuse** `ValidationIssue` / `ValidationSeverity` (`validation/model.py`) and the collect-don't-abort contract; severities **shall** round-trip through `color_policy.css_class_for_severity`. |
| C-6 | The target CDF version for read and write is **CDF 2.0** (`CATEGORY=CDF20`); reading **shall tolerate** other version tokens with an informational issue (design-input §2). |
| C-7 | The CDFX handler **shall not** modify, parse-against, or write the firmware S19/HEX image; the change-list and `.cdfx` are independent artifacts. |
| C-8 | New parsing/handler logic **shall live in a service-style module**, not inside `app.py`; `app.py` holds only UI-state wiring (`CLAUDE.md` TUI-layer rule). |
| C-9 | Snapshot/test fixtures involving `.cdfx` **shall use synthetic data only**, never client firmware/A2L/CDFX artifacts (consistent with `R-TUI-034`). |
| C-10 | The Patch Editor **shall not** write user-typed parameter values or file content to the `.s19tool/logs/` rotating log beyond the existing `set_status` behaviour (consistent with `R-TUI-035`). |

### 2.5 Assumptions and dependencies

| ID | Assumption — if false, the batch is invalidated or rescoped |
|----|-------------------------------------------------------------|
| A-1 | The CDFX structure documented in `design-input/cdfx-research.md` (the nine levels, `MSRSW`/`SW-INSTANCE`/`SW-VALUE-CONT`/`SW-VALUES-PHYS`/`V`/`VT`/`VG`) is an accurate description of CDF 2.0 as public sources describe it. The project owner inspected several real production `.cdfx` files — all produced by Vector CANape and carrying a `Created with CANape … CDF 2.0 Writer` tool-identification note — which corroborates the CDF 2.0 target (`design-input/cdfx-research.md` §2.1); no client `.cdfx` sample is bundled in the repo to confirm finer producer-specific variation. |
| A-2 | A change-list entry resolves against an A2L that is **already loaded** in the app; building a change-list without a loaded A2L yields unresolved entries (a warning state), not a hard error. |
| A-3 | The editable scope is **scalar** (`VALUE`/`BOOLEAN`) and **1-D array** (`VAL_BLK`) and **ASCII string** parameters — matching what `tui/a2l.py` decodes (`DATATYPE_SIZES`, `element_count`, array decode path). 2-D maps, axes and structured types are read-tolerated only. |
| A-4 | The change-list stores and writes **physical** values (CDF-correct); raw/hex rendering is a display concern only. |
| A-5 | vCDM consumes CDF 2.0 (`.cdfx`); compatibility is asserted from Vector documentation, not verified against a live vCDM instance. |
| A-6 | A saved `.cdfx` file is a **work-area-contained artifact**: it is written **into `.s19tool/workarea/`** and is protected by the **existing `s19_app/tui/workspace.py` containment guards** — the write target resolves under the work area, reparse-point (symlink / NTFS junction) traversal is rejected, and an existing-file target is dedup-suffixed (per `copy_into_workarea`). It is **not** bound into the `.s19tool/` *project* artifact set and is therefore **not** subject to `validate_project_files` (resolution of OQ-3) — but the path-containment guarantee that scoping removed from `validate_project_files` is **replaced**, not dropped: it is re-established by LLR-007.7 (write-path containment) and LLR-005.5 (load-path resolution). A `.cdfx` is an exchange artifact whose *project-membership* is out of scope, **not** an unconstrained free-path export (S-001). |

### 2.6 Source user stories

> Connextra format. Each US is traceable to one or more HLRs.

| ID | User Story | Source |
|----|------------|--------|
| US-001 | As a calibration engineer, I want to build a list of parameter changes keyed to A2L parameter names and array indices, so that I can capture exactly which calibration values I intend to change. | batch-03 objective; `R-TUI-027` follow-up |
| US-002 | As a calibration engineer, I want each change-list entry resolved against the loaded A2L, so that I know the parameter's data type and whether the name/index is valid before I commit a value. | batch-03 objective; constraint C-1 |
| US-003 | As a calibration engineer, I want each value shown in the form best suited to its A2L data type (decimal, hex, signed, float, ASCII string), so that I can read and verify values without manual conversion. | batch-03 objective item 1 |
| US-004 | As a calibration engineer, I want to save my change-list as a `.cdfx` file, so that I can hand it off to vCDM as a standard calibration-data exchange artifact. | batch-03 objective item 2 |
| US-005 | As a calibration engineer, I want to load a `.cdfx` file into the Patch Editor, so that I can review or continue editing a change-list produced earlier or elsewhere. | batch-03 objective item 2 |
| US-006 | As a calibration engineer, I want a malformed or unexpected `.cdfx` file to be reported as a list of issues rather than crashing the tool, so that I can see what is wrong and still work with whatever loaded correctly. | project validation culture; constraint C-5 |
| US-007 | As a calibration engineer, I want the Patch Editor screen to actually let me add, edit, remove, save and load change-list entries, so that the rail screen is a working tool instead of an inert preview. | `R-TUI-027` supersession |

---

## 3. High-level requirements (HLR)

> This section specifies **8 HLRs** (HLR-001…HLR-008), each tracing to one or
> more of the 7 user stories of §2.6 and each decomposed into LLRs in §4
> (44 LLRs total — see §1.5 and the §4 header).

### HLR-001 — Parameter change-list model
- **Traceability:** US-001, US-007
- **Statement:** The system shall maintain a parameter change-list in which
  each entry holds an A2L parameter name, an array index, and a value, and
  shall support adding, editing and removing entries.
- **Rationale (informative):** The change-list is the central artifact of the
  Patch Editor; it must exist as a structured model before it can be resolved,
  displayed or serialized.
- **Validation:** test
- **Priority:** high

### HLR-002 — Parameter resolution against the loaded A2L
- **Traceability:** US-002
- **Statement:** When a change-list entry is added or edited, the system shall
  resolve its parameter name and array index against the loaded A2L to
  determine the parameter's data type, element count and category, and shall
  mark the entry unresolved when no matching A2L parameter exists or the index
  is out of range.
- **Rationale (informative):** Resolution against A2L gives every entry its
  type metadata and validity status; it reuses the existing A2L parser per C-1.
- **Validation:** test
- **Priority:** high

### HLR-003 — Value entry and type-driven display format
- **Traceability:** US-003
- **Statement:** The system shall accept a value for each change-list entry and
  shall display that value in the form determined by the resolved A2L
  parameter — decimal for unsigned integers, with a hexadecimal companion only
  when the physical value is integral; signed decimal for signed integers;
  fractional decimal for IEEE floats; and a quoted string for ASCII/string
  (`ASCII`-`char_type`) parameters.
- **Rationale (informative):** "Best form" display, driven by the A2L data
  type, lets the engineer verify values without manual base conversion
  (design-input §6).
- **Validation:** test+demo
- **Priority:** high

### HLR-004 — CDFX write (produce a `.cdfx`)
- **Traceability:** US-004
- **Statement:** When the engineer saves the change-list, the system shall
  write a well-formed, structurally valid CDF 2.0 `.cdfx` file in which each
  resolved parameter is represented as exactly one `SW-INSTANCE` carrying its
  parameter name, category and physical value(s) — a scalar/string parameter
  from its single change-list entry, a 1-D array parameter from its
  array-element entries coalesced into one `VAL_BLK` `SW-INSTANCE`.
- **Rationale (informative):** A standard `.cdfx` is the deliverable handed to
  vCDM; the write must produce the schema-shaped structure of design-input §3
  and §5.
- **Validation:** test
- **Priority:** high

### HLR-005 — CDFX read (parse and validate a `.cdfx`)
- **Traceability:** US-005, US-006
- **Statement:** When the engineer loads a `.cdfx` file, the system shall parse
  it into change-list entries, shall validate it structurally, and shall
  collect every validation finding as a `ValidationIssue` without aborting the
  load.
- **Rationale (informative):** Reading must mirror the project's
  collect-don't-abort culture so the engineer sees all problems at once and
  still works with whatever parsed correctly.
- **Validation:** test
- **Priority:** high

### HLR-006 — CDFX validation rule set
- **Traceability:** US-006
- **Statement:** The system shall apply the CDFX write-time and read-time
  validation rules defined in `design-input/cdfx-research.md` §7, emitting one
  `ValidationIssue` per rule violation with the rule's defined code and
  severity.
- **Rationale (informative):** A fixed, documented rule set with stable issue
  codes is what makes "valid `.cdfx`" testable and keeps the contract stable
  for tests (consistent with the project's public issue-code policy).
- **Validation:** test
- **Priority:** high

### HLR-007 — Functional Patch Editor screen
- **Traceability:** US-007, US-001, US-004, US-005
- **Statement:** The system shall present the Patch Editor rail screen as a
  functional tool that lets the engineer build, edit and remove change-list
  entries and save the list to and load it from a `.cdfx` file, replacing the
  inert view shell delivered under `R-TUI-027`.
- **Rationale (informative):** US-007 closes the deferral declared by
  `R-TUI-027`; the screen must become the interactive surface for HLR-001,
  HLR-004 and HLR-005.
- **Validation:** test+demo
- **Priority:** high

### HLR-008 — Cross-check of a loaded `.cdfx` against the A2L
- **Traceability:** US-002, US-005, US-006
- **Statement:** When a `.cdfx` file is loaded while an A2L is loaded, the
  system shall cross-check each parsed `SW-INSTANCE` against the A2L and shall
  emit a warning-level `ValidationIssue` for any instance whose name does not
  match an A2L parameter or whose array length differs from the A2L element
  count.
- **Rationale (informative):** Cross-checking surfaces stale or mismatched
  change-lists, analogous to the existing A2L↔MAC cross-checks.
- **Validation:** test
- **Priority:** medium

---

## 4. Low-level requirements (LLR)

> This section specifies **44 LLRs** (authoritative count, Phase 3
> array-coalescing amendment): 4 (LLR-001.x) + 4 (LLR-002.x) + 3 (LLR-003.x) +
> 9 (LLR-004.x) + 6 (LLR-005.x) + 8 (LLR-006.x) + 7 (LLR-007.x) +
> 3 (LLR-008.x) = 44. Every LLR traces to exactly one parent HLR; every HLR
> (HLR-001…HLR-008) is decomposed here. The Phase-3 amendment added LLR-004.9
> (writer array-coalescing + sparse-array rule) and LLR-005.6 (reader
> `VAL_BLK` expansion); both need new test cases — see §5.7.

### LLR-001.1 — Change-list entry data structure
- **Traceability:** HLR-001
- **Statement:** The change-list model shall represent each entry as a
  structured record holding at least the fields `parameter_name` (str),
  `array_index` (`Optional[int]`), `value` (the entered physical value), and a
  resolution-status field. The `array_index` field shall be `None` for a
  **scalar** parameter (`VALUE` / `BOOLEAN`) and for an **ASCII string**
  parameter, and shall be a **non-negative integer** *k* for element *k* of a
  **1-D array** parameter (`VAL_BLK`).
- **Rationale (informative):** `array_index` was `int` with default `0` in the
  iteration-3 model, which made a scalar entry and element 0 of a single-element
  array **indistinguishable** — both are `(name, 0)`. The CDFX writer
  cannot then decide whether to emit a scalar `VALUE` `SW-INSTANCE` with a bare
  `V` or a `VAL_BLK` `SW-INSTANCE` with a `VG`, and the coalesce/expand contract
  of LLR-004.3 / LLR-004.9 / LLR-005.6 is unimplementable. Making `array_index`
  `Optional[int]` — `None` ≙ "not an array element" (scalar or string), `int`
  ≙ "array element *k*" — gives the writer and reader an unambiguous
  scalar-vs-array discriminator. This amends the iteration-3 model
  (`s19_app/tui/cdfx/changelist.py`) and is a phase-3 hand-off item.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - An entry can be constructed with name and index and reports its fields.
  - A scalar parameter and an ASCII parameter each carry `array_index = None`.
  - Element *k* of a 1-D array parameter carries `array_index = k` (`k >= 0`).

### LLR-001.2 — Add / edit / remove operations
- **Traceability:** HLR-001
- **Statement:** The change-list model shall provide operations to add an
  entry, edit the value of an existing entry identified by name + index, and
  remove an entry identified by name + index.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Adding then removing the same key leaves the list empty.
  - Editing an entry changes only that entry's value.

### LLR-001.3 — Entry identity and duplicate handling
- **Traceability:** HLR-001
- **Statement:** The change-list model shall treat the pair (`parameter_name`,
  `array_index`) — where `array_index` is `None` for a scalar/string entry and
  an integer for an array-element entry (LLR-001.1) — as the entry identity,
  and when an add targets an existing identity it shall update that entry
  rather than create a duplicate.
- **Rationale (informative):** Because `array_index` is now `Optional[int]`,
  `(name, None)` and `(name, 0)` are distinct identities: a scalar entry and
  element 0 of an array under the same parameter name are different rows. This
  is intentional — a parameter is either scalar or an array, never both, so the
  two identities never legitimately coexist for one A2L parameter; resolution
  (HLR-002) is what confirms which one is correct.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Adding `PARAM[0]` (array element 0) twice yields one entry with the latest
    value.
  - A scalar entry `(PARAM, None)` and an array entry `(PARAM, 0)` are distinct
    identities.

### LLR-001.4 — Change-list ordering is deterministic
- **Traceability:** HLR-001
- **Statement:** The change-list model shall expose its entries in a
  deterministic order so that repeated serialization of the same change-list
  produces byte-identical `SW-INSTANCE` ordering.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Two writes of the same change-list produce identical instance order.

### LLR-002.1 — Resolve a parameter against the loaded A2L
- **Traceability:** HLR-002
- **Statement:** The resolution function shall look up `parameter_name` among
  the **enriched** A2L tags — the tags produced by
  `enrich_a2l_tags_with_values` over the `tui/a2l.py` parsed payload, not the
  bare `extract_a2l_tags` output — and shall return the matched tag's
  `datatype`, `decode_type`, `char_type`, `element_count`/`length`, and
  section/category.
- **Rationale (informative):** A tag produced by a bare `extract_a2l_tags`
  call for a `CHARACTERISTIC` has `datatype = None`; the decode-relevant fields
  (`decode_type`, `element_count`, `char_type`) are populated only after
  `enrich_a2l_tags_with_values` / `_resolve_record_layout` has resolved the
  `RECORD_LAYOUT` and `COMPU_METHOD`. Resolving against the unenriched object
  would mark every characteristic unresolved (A-01).
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A name present in the A2L resolves with its data type, after enrichment.
  - The function calls into `tui/a2l.py` (via the enriched pipeline) and does
    not re-parse A2L text.

### LLR-002.2 — Unresolved-name handling
- **Traceability:** HLR-002
- **Statement:** If a change-list entry's `parameter_name` matches no A2L
  parameter, then the resolution function shall mark the entry `unresolved`
  and shall not raise an exception.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - An unknown name produces an `unresolved` entry, list still usable.

### LLR-002.3 — Array-index range check
- **Traceability:** HLR-002
- **Statement:** If a change-list entry's `array_index` is an integer that is
  negative or not less than the resolved A2L `element_count`, then the
  resolution function shall mark the entry `index-out-of-range` and shall not
  raise an exception. An entry whose `array_index` is `None` (a scalar or
  string entry, LLR-001.1) is not subject to the range check.
- **Rationale (informative):** With `array_index` now `Optional[int]`
  (LLR-001.1), only an array-element entry carries an integer index to
  range-check; a scalar/string entry's `array_index` is `None` and the range
  check does not apply to it. A scalar entry against a parameter the A2L
  reports with `element_count = 1` resolves on name alone.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Integer index `5` on a 3-element array parameter is flagged
    `index-out-of-range`.
  - A scalar entry (`array_index is None`) against a scalar A2L parameter
    (`element_count = 1`) resolves normally.

### LLR-002.4 — Resolution without a loaded A2L
- **Traceability:** HLR-002
- **Statement:** While no A2L is loaded, the resolution function shall mark
  every change-list entry `unresolved-no-a2l` and shall not raise an exception.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - With no A2L, entries are still listed, all marked `unresolved-no-a2l`.

### LLR-003.1 — Display-format selection from A2L data type
- **Traceability:** HLR-003
- **Statement:** The value-formatting function shall select the display form
  from the pair (`char_type`, `datatype`) of the resolved A2L parameter, in
  this order: when `char_type` is `ASCII` the value renders as a quoted
  string; otherwise the `datatype` token selects the form — unsigned integer
  types (`UBYTE`, `UWORD`, `ULONG`, `A_UINT64`) render as decimal, accompanied
  by hexadecimal **only when the physical value is integral** (see
  LLR-003.1's integral-hex condition below); signed integer types (`SBYTE`,
  `SWORD`, `SLONG`, `A_INT64`) render as signed decimal; IEEE float types
  (`FLOAT16_IEEE`, `FLOAT32_IEEE`, `FLOAT64_IEEE`) render as fractional
  decimal.
- **Statement (integral-hex condition):** The hexadecimal companion shall be
  shown for an unsigned-integer parameter only when the stored physical value
  is integral (an exact integer with no fractional part); when the parameter's
  `COMPU_METHOD` is non-IDENTICAL and yields a fractional physical value, the
  function shall render decimal only and shall not attempt a hexadecimal
  companion.
- **Rationale (informative):** `ASCII` is an A2L `char_type` /
  characteristic-kind attribute, orthogonal to the numeric `datatype`; there is
  no `ASCII` `datatype` token, so the quoted-string form must be selected from
  `char_type`, not `datatype` (A-02). Separately, `hex()` of a fractional
  physical value has no meaning: the change-list stores the **physical** value
  (DD-3 / LLR-003.3), and a non-IDENTICAL `COMPU_METHOD` produces a fractional
  physical value — so the hexadecimal companion is well-defined only when the
  physical value is integral, i.e. effectively for IDENTICAL-conversion
  parameters (A-03).
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - `UBYTE` value 23 (IDENTICAL conversion) renders as `23` / `0x17`.
  - An unsigned parameter with a non-IDENTICAL `COMPU_METHOD` whose physical
    value is fractional renders decimal only, with no hexadecimal companion.
  - A negative `SWORD` renders with a leading sign.
  - A `FLOAT32_IEEE` renders with a fractional part.
  - An `ASCII`-`char_type` parameter renders as a quoted string.

### LLR-003.2 — Display-format fallback for unresolved entries
- **Traceability:** HLR-003
- **Statement:** While an entry is unresolved (no A2L data type available), the
  value-formatting function shall render the value as plain decimal text and
  shall not raise an exception.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - An unresolved entry's value still renders without error.

### LLR-003.3 — Value entry is stored as a physical value
- **Traceability:** HLR-003
- **Statement:** The change-list model shall store the entered value as the
  physical value of the parameter, and the hexadecimal/ASCII rendering shall be
  derived for display only and shall not alter the stored value.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - The stored value equals the entered physical value regardless of display
    form.

### LLR-004.1 — CDFX writer emits the CDF 2.0 backbone
- **Traceability:** HLR-004
- **Statement:** The CDFX writer shall emit an `MSRSW` root containing a
  non-empty `SHORT-NAME`, a `CATEGORY` of `CDF20`, and the
  `SW-SYSTEMS/SW-SYSTEM/SW-INSTANCE-SPEC/SW-INSTANCE-TREE` element chain, each
  container element carrying a `SHORT-NAME`.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Output root tag is `MSRSW`; `CATEGORY` text is `CDF20`.
  - The instance-tree backbone chain is present.

### LLR-004.2 — CDFX writer emits one `SW-INSTANCE` per resolved parameter
- **Traceability:** HLR-004
- **Statement:** The CDFX writer shall emit **exactly one `SW-INSTANCE` per
  distinct resolved `parameter_name`** — not one per change-list entry — each
  `SW-INSTANCE` containing a `SHORT-NAME` equal to the parameter name, a
  `CATEGORY` from the editable set (`VALUE` for scalar parameters, `BOOLEAN`
  for boolean-like scalar parameters, `VAL_BLK` for 1-D array parameters,
  `ASCII` for string parameters), and a `SW-VALUE-CONT/SW-VALUES-PHYS`
  element. A scalar/string parameter contributes one change-list entry and
  therefore one `SW-INSTANCE`; a 1-D array parameter contributes one
  change-list entry **per element index** and the writer **shall coalesce**
  those entries into a single `VAL_BLK` `SW-INSTANCE` per LLR-004.9.
- **Rationale (informative):** The iteration-3 change-list model keys entries
  by `(parameter_name, array_index)` (LLR-001.1 / LLR-001.3), so a 3-element
  array characteristic is **three** `ChangeListEntry` rows. Standard ASAM CDF
  2.0 (`design-input/cdfx-research.md` §3, §5) represents an array parameter as
  **one** `SW-INSTANCE` (`CATEGORY=VAL_BLK`) whose `SW-VALUE-CONT/`
  `SW-VALUES-PHYS` carries a single `VG` of positional `V`. Emitting one
  `SW-INSTANCE` per entry would produce repeated same-`SHORT-NAME` instances,
  which is **not standard CDF** and which vCDM — the interop target — would
  mis-read or reject. "One `SW-INSTANCE` per resolved parameter" is therefore
  the correct unit; LLR-004.9 specifies the coalescing that achieves it.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A scalar entry produces one `SW-INSTANCE` with `CATEGORY` `VALUE`.
  - Three array-element entries (`PARAM[0]`, `PARAM[1]`, `PARAM[2]`) of the
    same `parameter_name` produce **exactly one** `SW-INSTANCE`, not three.
  - The instance `SHORT-NAME` equals the change-list parameter name.

### LLR-004.3 — CDFX writer encodes scalar and array values
- **Traceability:** HLR-004
- **Statement:** The CDFX writer shall select the `SW-VALUES-PHYS` value
  encoding from the entry's `array_index` (LLR-001.1): a **scalar** entry
  (`array_index is None`, `CATEGORY` `VALUE` or `BOOLEAN`) shall be encoded as
  a **single bare `V`** element directly inside `SW-VALUES-PHYS`; an **ASCII
  string** entry (`array_index is None`, `CATEGORY` `ASCII`) shall be encoded
  as a **single `VT`** element directly inside `SW-VALUES-PHYS`; a **1-D array**
  parameter (entries whose `array_index` is an integer, `CATEGORY` `VAL_BLK`)
  shall be encoded as a **single `VG`** element inside `SW-VALUES-PHYS`
  containing one positional `V` per array element, the `V` elements ordered
  **ascending by `array_index`** (the coalescing of LLR-004.9 produces this
  `VG`). The change-list field `array_index` shall be serialized **only** as
  the positional order of the `V` elements inside the `VG`; it shall **not** be
  emitted as a CDFX `SW-ARRAY-INDEX` element.
- **Rationale (informative):** With `array_index` now `Optional[int]`
  (LLR-001.1), the writer has an unambiguous discriminator: `None` ⇒ scalar or
  string (one bare `V` or one `VT`), integer ⇒ one element of an array (a `V`
  inside the coalesced `VG`). The change-list field `array_index` and the CDFX
  element `SW-ARRAY-INDEX` remain different concepts: `array_index` is the
  change-list entry's positional key (element *k* of a single 1-D array
  characteristic), whereas `SW-ARRAY-INDEX` (research §3) is an unrelated CDFX
  construct that appears only when a `SW-INSTANCE` is itself an element of an
  array-of-parameters (`*_ARRAY` categories, out of scope this batch). The
  similar names invite mis-serialization; this clause forbids it (A-09).
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A scalar entry produces one bare `V` directly under `SW-VALUES-PHYS`.
  - A 3-element array produces one `VG` with three `V` children ordered
    ascending by `array_index`.
  - A string parameter produces one `VT`.
  - No `SW-ARRAY-INDEX` element appears in the writer output.

### LLR-004.4 — CDFX writer output is well-formed UTF-8 XML
- **Traceability:** HLR-004
- **Statement:** The CDFX writer shall produce well-formed XML encoded in UTF-8
  with an XML declaration, parseable without error by `xml.etree.ElementTree`.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - The written file re-parses via `ElementTree` without exception.

### LLR-004.5 — Unresolved entries are excluded from the write with a warning
- **Traceability:** HLR-004, HLR-006
- **Statement:** If the change-list contains unresolved or index-out-of-range
  entries when a write is requested, then the CDFX writer shall exclude those
  entries from the output and shall emit one warning-level `ValidationIssue`
  with code **`W-INSTANCE-EXCLUDED`** per excluded entry.
- **Rationale (informative):** `W-INSTANCE-EXCLUDED` is the formally adopted
  code for the per-entry exclusion warning. It is a writer **behavior** code
  (it flags a writer decision — "this entry was dropped"), distinct from the
  eight `W-*` structural **rule** codes of `design-input/cdfx-research.md` §7
  which flag a *malformed output*. Increment 4 introduced the name ad-hoc; the
  Phase-1 decision (this amendment) is to **keep it** rather than rename it —
  it is descriptive, already implemented and tested, and §7 already separates
  writer *behaviors* (the tool-note, round-trip floats) from issue-emitting
  *rules*. `design-input/cdfx-research.md` §7 is updated to list
  `W-INSTANCE-EXCLUDED` (and the related `W-ARRAY-SPARSE` of LLR-004.9) under
  a "writer-behavior codes" heading so the code set is complete and traceable.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - An unresolved entry produces no `SW-INSTANCE` and one `W-INSTANCE-EXCLUDED`
    warning issue.

### LLR-004.6 — Empty-change-list write is reported
- **Traceability:** HLR-004, HLR-006
- **Statement:** If a write is requested for a change-list with zero writable
  entries — whether the change-list is literally empty **or** every entry was
  excluded as unresolved/index-out-of-range by LLR-004.5 — then the CDFX writer
  shall still emit a valid backbone-only `.cdfx` and shall emit exactly one
  warning-level `ValidationIssue` with code `W-EMPTY-CHANGELIST`, in addition
  to any per-entry LLR-004.5 exclusion warnings.
- **Rationale (informative):** `W-EMPTY-CHANGELIST` fires on the
  zero-*writable* condition, not only on a literally-empty change-list. A
  two-entry all-unresolved change-list therefore emits two LLR-004.5 exclusion
  warnings plus one `W-EMPTY-CHANGELIST` — three warnings total — which is the
  intended behavior: the per-entry warnings explain *why* nothing was written
  and `W-EMPTY-CHANGELIST` flags the resulting empty deliverable (A-05).
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A literally-empty change-list yields a valid `MSRSW` file plus one
    `W-EMPTY-CHANGELIST` warning.
  - A change-list of two all-unresolved entries yields a valid backbone-only
    `MSRSW` file plus two LLR-004.5 warnings and one `W-EMPTY-CHANGELIST`.

### LLR-004.7 — CDFX writer emits a tool-identification note
- **Traceability:** HLR-004
- **Statement:** The CDFX writer shall emit a tool-identification note that
  identifies s19_app as the producing tool — a leading XML comment of the form
  `Created with s19_app CDF 2.0 Writer` — placed so that the output remains
  well-formed XML and re-parseable by `xml.etree.ElementTree`.
- **Rationale (informative):** production `.cdfx` files in the
  Vector-CANape-dominated ecosystem carry a writer/tool-identification note
  (`design-input/cdfx-research.md` §2.1); emitting one makes s19_app-produced
  files self-describing and consistent with that ecosystem.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A written `.cdfx` carries a leading `Created with s19_app CDF 2.0 Writer`
    XML comment and still re-parses via `ElementTree` without exception.

### LLR-004.8 — CDFX writer emits round-trip-safe float values
- **Traceability:** HLR-004
- **Statement:** When the CDFX writer encodes an IEEE float physical value as a
  `V` element, it shall emit the value in a round-trip-safe textual
  representation that preserves full precision (equivalent to Python `repr()`
  of the float), so that a write→read cycle of the same value is exact and no
  float tolerance is required to compare written and re-read values.
- **Rationale (informative):** a full-precision decimal representation
  guarantees the round-trip test TC-024 can assert exact equality on float
  values rather than relying on a tolerance, removing the float-equality
  ambiguity raised in OQ-6. This LLR governs the **per-`V`-value** precision
  half of the round-trip; the **structural** half — that coalesce-on-write
  (LLR-004.9) then expand-on-read (LLR-005.6) reproduces the
  `(parameter_name, array_index)` key set exactly — is stated normatively in
  LLR-004.9's round-trip clause. TC-024 verifies both halves together.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A float physical value written then re-read by the CDFX reader compares
    exactly equal to the original, with no tolerance applied.

### LLR-004.9 — CDFX writer coalesces array-element entries into one `SW-INSTANCE`
- **Traceability:** HLR-004
- **Statement:** Before emitting `SW-INSTANCE` elements, the CDFX writer shall
  **coalesce** all resolved change-list entries that share a `parameter_name`
  and whose `array_index` is an integer into a **single `SW-INSTANCE`** with
  `CATEGORY=VAL_BLK`, whose `SW-VALUE-CONT/SW-VALUES-PHYS` carries **one `VG`**
  containing one positional `V` per coalesced entry, the `V` elements ordered
  **ascending by `array_index`** (LLR-004.3). A resolved entry whose
  `array_index` is `None` shall **not** be coalesced and shall be emitted as
  its own single-element `SW-INSTANCE` (`VALUE` / `BOOLEAN` with a bare `V`, or
  `ASCII` with a `VT`, per LLR-004.2 / LLR-004.3).
- **Statement (sparse-array rule — normative):** If the integer `array_index`
  values of the coalesced group for one `parameter_name` do **not** form the
  **contiguous, gapless, zero-based sequence** `0, 1, …, N-1` (where `N` is the
  count of entries in the group) — for example entries exist for index 0 and
  index 2 but not index 1, or the lowest index is not 0 — then the writer
  **shall treat the array as a write-side error**: it shall **exclude the
  entire `parameter_name` group from the output** (emit no `SW-INSTANCE` for
  it) and shall emit **exactly one** warning-level `ValidationIssue` with code
  **`W-ARRAY-SPARSE`** naming that `parameter_name`. The writer **shall not**
  gap-fill, default, interpolate, or otherwise synthesize a value for a missing
  index.
- **Statement (round-trip — normative):** For a change-list whose entries are
  all resolved and all writable (no unresolved / index-out-of-range entry, and
  every array group contiguous and zero-based), coalesce-on-write (this LLR,
  LLR-004.3) followed by expand-on-read (LLR-005.6) shall **reproduce the
  change-list entry set exactly** — the recovered change-list shall hold the
  same set of `(parameter_name, array_index)` keys and, per key, the same
  value (exact equality, with float values exact per LLR-004.8) and the same
  category — so a write→read cycle is lossless.
- **Rationale (informative):** Standard ASAM CDF 2.0 (`design-input/`
  `cdfx-research.md` §3, §5) has **no per-element index attribute** for a
  simple 1-D array — element *k* is *positionally* the *(k+1)*-th `V` inside
  the `VG`. A sparse change-list (a gap, or a non-zero lowest index) cannot be
  represented positionally without **inventing** a value for the missing slot.
  Two write-side rules were considered: **(a) gap-fill** the missing index with
  a default/zero/last value, or **(b) reject** the whole array group. Rule (b)
  is chosen and made normative because gap-filling would write a **physical
  value the engineer never entered** into a `V` slot — silently shipping an
  unintended calibration value to the ECU via vCDM — which directly violates
  the "store the entered physical value verbatim" contract (DD-3 / LLR-003.3)
  and the project's fail-loud culture (`CLAUDE.md` engineering rule 12). A
  sparse array is almost always an *editing mistake* (the engineer forgot an
  element); rejecting it with a named warning surfaces the mistake instead of
  masking it, and the decision is fully reversible — the engineer adds the
  missing index and re-saves. The `W-ARRAY-SPARSE` exclusion participates in
  the zero-writable-entries accounting of LLR-004.6 exactly as the LLR-004.5
  exclusion does: if every group is excluded the writer still emits a valid
  backbone-only `.cdfx` plus one `W-EMPTY-CHANGELIST`.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Three entries `PARAM[0]`, `PARAM[1]`, `PARAM[2]` of one `parameter_name`
    produce exactly one `VAL_BLK` `SW-INSTANCE` with a three-`V` `VG` ordered
    `[0],[1],[2]`.
  - Entries for `PARAM[0]` and `PARAM[2]` only (index 1 missing) produce **no**
    `SW-INSTANCE` for `PARAM` and exactly one `W-ARRAY-SPARSE` warning naming
    `PARAM`.
  - Entries for `PARAM[1]` and `PARAM[2]` only (lowest index is 1, not 0)
    produce **no** `SW-INSTANCE` for `PARAM` and one `W-ARRAY-SPARSE` warning.
  - The writer never emits a `V` for an index the change-list did not contain.
- **qa-reviewer note:** this LLR is **new** and needs a dedicated test case —
  see the §5 hand-off note. A new `TC-038` is recommended (writer coalescing +
  the sparse-array rejection), and the new code `W-ARRAY-SPARSE` must be added
  to the §5.7 rule-code coverage and to the `make_rule_violation_cdfx` /
  writer-fixture set.

### LLR-005.1 — CDFX reader parses well-formed files into entries
- **Traceability:** HLR-005
- **Statement:** The CDFX reader shall parse a well-formed `.cdfx` file with
  `xml.etree.ElementTree`, locate each `SW-INSTANCE` under the instance-tree
  backbone, and produce change-list entries from each readable instance — one
  scalar/string entry per `VALUE` / `BOOLEAN` / `ASCII` instance and, per
  LLR-005.6, *N* array-element entries per `VAL_BLK` instance whose `VG` holds
  *N* values — each entry carrying its parameter name, `array_index`, value,
  and category.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A file written by the writer round-trips back to an equivalent change-list.

### LLR-005.2 — CDFX reader tolerates malformed XML
- **Traceability:** HLR-005, HLR-006
- **Statement:** If the `.cdfx` file is not well-formed XML, then the CDFX
  reader shall emit one error-level `ValidationIssue` with code `R-XML-PARSE`
  and shall return an empty change-list without raising an exception.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A truncated/garbage file produces one `R-XML-PARSE` issue, no crash.

### LLR-005.3 — CDFX reader tolerates producer-specific variation
- **Traceability:** HLR-005
- **Statement:** The CDFX reader shall locate `MSRSW`, the instance-tree
  backbone and each `SW-INSTANCE` by element **local name regardless of XML
  namespace** — when a default `xmlns` is declared, `xml.etree.ElementTree`
  returns tags in `{uri}LocalName` form, so the reader shall match on the
  local name with any namespace prefix or URI stripped. The reader shall locate
  `SW-INSTANCE` elements **only as descendants of the `SW-INSTANCE-TREE`
  backbone**, not anywhere in the document, and shall ignore unrecognized
  optional sibling elements (for example `ADMIN-DATA`, `SW-CS-HISTORY`,
  `SW-CS-FLAGS`) and any element it does not recognize.
- **Rationale (informative):** A default `xmlns` on the `MSRSW` root makes
  `ElementTree` namespace-qualify every tag, so a literal string match on
  `MSRSW` / `SW-INSTANCE` / `V` would fail on a perfectly valid namespaced
  `.cdfx` (A-06, RK-3). Scoping the `SW-INSTANCE` search to the
  `SW-INSTANCE-TREE` backbone prevents a crafted `.cdfx` from placing
  `SW-INSTANCE` elements outside the legitimate instance-tree (for example
  inside `ADMIN-DATA`) and having them silently absorbed as real change-list
  entries (S-006).
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A file with extra optional elements and a declared `xmlns` still reads all
    instances.
  - A `SW-INSTANCE` element placed outside the `SW-INSTANCE-TREE` backbone is
    not absorbed into the change-list.

### LLR-005.4 — CDFX reader decodes numeric value notations
- **Traceability:** HLR-005
- **Statement:** The CDFX reader shall decode the text content of a `V` element
  expressed in decimal, exponential, or hexadecimal (`0x`-prefixed) notation
  into a numeric value, and shall decode binary notation in the form defined by
  CDF.
- **Rationale (informative):** Research §3 establishes that CDF allows `V` text
  in decimal, exponential, hexadecimal and binary notation but does not pin the
  exact binary-prefix lexeme. The `0b` prefix is the Python integer-literal
  form and is **not** confirmed by the research as the CDF binary notation —
  this LLR therefore states "binary notation in the form defined by CDF" rather
  than hard-coding `0b`. The concrete binary lexeme is recorded as an open
  question (OQ-7); until it is resolved against a real `.cdfx` or the CDF
  specification, the implementation may accept `0b` as a tolerant superset but
  no test asserts `0b` as the normative form (A-07).
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - `<V>0x17</V>` decodes to 23; `<V>1.5e1</V>` decodes to 15.0.

### LLR-005.5 — CDFX load path resolves the user-supplied path
- **Traceability:** HLR-005
- **Statement:** When the CDFX reader is invoked with a user-supplied `.cdfx`
  path, it shall resolve that path through `s19_app/tui/workspace.py`
  `resolve_input_path` before opening the file — reusing the existing helper,
  not re-implementing path resolution — and shall reject a path that
  `resolve_input_path` cannot resolve by surfacing one `ValidationIssue` with
  code `R-XML-PARSE` rather than opening an unresolved or arbitrary location.
- **Rationale (informative):** Every other user-typed input path in the app is
  resolved through `resolve_input_path`, which walks the app cwd and the
  nearest repo root. Without that discipline a user-typed `.cdfx` path could be
  a symlink / NTFS junction or point to an arbitrary location off the work
  area, read with no stated guard (S-002). Reading a `.cdfx` from outside the
  work area is **permitted** — a `.cdfx` is an exchange artifact that may
  legitimately arrive from elsewhere — but the path must still be *resolved*
  through the shared helper so resolution is uniform and reparse-point handling
  is consistent with the rest of the app.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A valid `.cdfx` path is resolved via `resolve_input_path` and read.
  - An unresolvable path yields one `R-XML-PARSE` issue and no file is opened.

### LLR-005.6 — CDFX reader expands a `VAL_BLK` instance into array-element entries
- **Traceability:** HLR-005
- **Statement:** When the CDFX reader reads a `SW-INSTANCE`, it shall produce
  change-list entries from the instance `CATEGORY` and value shape as follows:
  a `VALUE` or `BOOLEAN` instance carrying a single `V` shall produce **one
  scalar entry** with `array_index = None`; an `ASCII` instance carrying a
  single `VT` shall produce **one string entry** with `array_index = None`; a
  `VAL_BLK` instance whose `SW-VALUE-CONT/SW-VALUES-PHYS` carries a `VG` of *N*
  `V` elements shall be **expanded** into **N change-list entries** for that
  `parameter_name`, the *i*-th `V` (zero-based) producing the entry
  `(parameter_name, array_index = i)` — so the entries span the contiguous
  index range `0 … N-1`.
- **Rationale (informative):** This is the read-side inverse of the LLR-004.9
  write-side coalescing. The writer collapses *N* `(name, 0..N-1)` entries into
  one `VAL_BLK` `SW-INSTANCE` with an *N*-element `VG`; the reader must expand
  that same `SW-INSTANCE` back into the *N* keyed entries so the change-list
  model (LLR-001.1) — which has no native "array" row, only per-element rows —
  is reconstructed faithfully. Because the writer only ever emits a gapless
  zero-based `VG` (LLR-004.9 rejects sparse arrays before write), positional
  expansion to `0 … N-1` is exact and unambiguous for any `.cdfx` s19_app
  itself produced. A `VAL_BLK` instance from a foreign producer is expanded the
  same way (positional `V` order is the CDF contract, research §3); a foreign
  `VAL_BLK` whose `V` count disagrees with the A2L `element_count` is still
  surfaced by the LLR-008.2 `R-ARRAY-LEN-MISMATCH` cross-check.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A `VAL_BLK` instance with a three-`V` `VG` expands to three entries
    `(PARAM, 0)`, `(PARAM, 1)`, `(PARAM, 2)`.
  - A `VALUE` instance expands to one entry with `array_index = None`.
  - An `ASCII` instance expands to one string entry with `array_index = None`.
- **qa-reviewer note:** this LLR is **new** and needs a dedicated test case —
  a new `TC-039` is recommended (reader expansion of `VAL_BLK`/`VALUE`/`ASCII`
  into the correct `array_index` shape). See the §5 hand-off note.

### LLR-006.1 — Write-time validation rule set
- **Traceability:** HLR-006
- **Statement:** The CDFX writer shall apply the eight write-time **structural
  rules** of `design-input/cdfx-research.md` §7 — `W-XML-WELLFORMED`,
  `W-ROOT-MSRSW`, `W-BACKBONE`, `W-INSTANCE-NAME`, `W-INSTANCE-CATEGORY`,
  `W-VALUE-PRESENT`, `W-CATEGORY-VALUE-CONSISTENT`, `W-EMPTY-CHANGELIST` —
  emitting one `ValidationIssue` with the rule's code and severity per
  violation; and the writer shall, in addition, emit the two write-time
  **behavior** codes `W-INSTANCE-EXCLUDED` (LLR-004.5, per excluded
  unresolved / index-out-of-range entry) and `W-ARRAY-SPARSE` (LLR-004.9, per
  rejected sparse array group), each as one warning-level `ValidationIssue`.
- **Rationale (informative):** The eight `W-*` of §7 flag a *malformed
  writer output*; `W-INSTANCE-EXCLUDED` and `W-ARRAY-SPARSE` flag a *writer
  decision to drop input that cannot be represented* (an unresolved entry, or a
  sparse array that has no positional CDF encoding). Both kinds are
  `ValidationIssue`s with stable codes; the distinction is documentation only,
  recorded so the §7 rule-code set and the §5.7 coverage table both stay
  complete and no code is "drift".
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Each write-time structural rule code can be provoked and is emitted with
    the documented severity.
  - `W-INSTANCE-EXCLUDED` and `W-ARRAY-SPARSE` are each emitted as a
    warning-level `ValidationIssue` by their LLR-004.5 / LLR-004.9 paths.

### LLR-006.2 — Read-time validation rule set
- **Traceability:** HLR-006
- **Statement:** The CDFX reader shall apply the read-time rules of
  `design-input/cdfx-research.md` §7 — `R-XML-PARSE`, `R-ROOT-MSRSW`,
  `R-VERSION-UNKNOWN`, `R-BACKBONE-MISSING`, `R-INSTANCE-NO-NAME`,
  `R-INSTANCE-NO-VALUE`, `R-CATEGORY-UNSUPPORTED`, `R-CATEGORY-VALUE-MISMATCH`,
  `R-VALUE-NOT-NUMERIC` — emitting one `ValidationIssue` with the rule's code
  and severity per violation.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Each read-time rule code can be provoked and is emitted with the
    documented severity.

### LLR-006.3 — Issues reuse the project ValidationIssue model
- **Traceability:** HLR-006
- **Statement:** Every CDFX validation finding shall be a `ValidationIssue`
  (`s19_app/validation/model.py`) with `artifact` set to `cdfx`, and its
  `severity` shall round-trip through `color_policy.css_class_for_severity`.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A CDFX issue's severity yields a valid `sev-*` CSS class.

### LLR-006.4 — Version-token tolerance on read
- **Traceability:** HLR-006
- **Statement:** If a loaded `.cdfx` file's `MSRSW/CATEGORY` is not `CDF20`,
  then the CDFX reader shall emit one info-level `ValidationIssue` with code
  `R-VERSION-UNKNOWN` and shall continue parsing the file.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A `CDF21` file reads its instances and produces one `R-VERSION-UNKNOWN`
    info issue.

### LLR-006.5 — Unsupported instance categories are read-only, not fatal
- **Traceability:** HLR-006
- **Statement:** If a `SW-INSTANCE` declares a `CATEGORY` outside the supported
  editable set (`VALUE`, `BOOLEAN`, `VAL_BLK`, `ASCII`) — for example `MAP`,
  `STRUCTURE` or a `*_ARRAY` type — then the CDFX reader shall emit one
  warning-level `ValidationIssue` with code `R-CATEGORY-UNSUPPORTED`, shall
  mark the resulting entry read-only, and shall not raise an exception.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A `MAP` instance loads as a read-only entry with one warning issue.

### LLR-006.6 — XML entity / DOCTYPE rejection on read
- **Traceability:** HLR-006
- **Statement:** The CDFX reader shall reject any `.cdfx` input that contains a
  `DOCTYPE` declaration or an `<!ENTITY>` declaration: it shall parse with an
  `xml.etree.ElementTree.XMLParser` whose DTD / entity-declaration handler
  raises on the first such declaration, and shall surface the rejection as
  exactly one `ValidationIssue` with code `R-XML-PARSE`, returning an empty
  change-list without exhausting memory, hanging, reading any external file, or
  raising an uncaught exception.
- **Rationale (informative):** A conformant CDF 2.0 `.cdfx` needs no `DOCTYPE`
  and no `<!ENTITY>` declaration, so rejecting them costs nothing on valid
  input. Stdlib `xml.etree.ElementTree` has **no expansion-count bound** and
  **still expands INTERNAL general entities** — a billion-laughs payload with
  no `SYSTEM` reference therefore still amplifies unboundedly, so "disabled or
  safely bounded" describes a mitigation the stdlib does not provide (S-004).
  Rejecting the `DOCTYPE` / `<!ENTITY>` declaration *before* any entity can be
  declared or expanded is the concrete, deterministic, **stdlib-only** defense
  — it neutralizes both the billion-laughs (internal-entity) and the
  external-entity (`SYSTEM`/`PUBLIC`) vectors with one rule. **C-2-vs-security
  decision (recorded):** no `defusedxml` (or any other) dependency is
  introduced — `DOCTYPE`-rejection via a custom `XMLParser` handler is the
  stdlib answer that satisfies constraint C-2; see DD-9. This LLR is a parent
  requirement for security test case TC-027.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A billion-laughs `.cdfx` (a `DOCTYPE` with nested `<!ENTITY>` declarations)
    produces exactly one `R-XML-PARSE` issue; the parser never expands an
    entity; no memory exhaustion, no hang, no uncaught exception.
  - An external-entity (`SYSTEM`) `.cdfx` produces exactly one `R-XML-PARSE`
    issue and no external file is read.
  - A well-formed `.cdfx` with no `DOCTYPE` parses normally with no
    `R-XML-PARSE` issue from this rule.

### LLR-006.7 — Reader tolerates writer / tool-identification notes
- **Traceability:** HLR-006
- **Statement:** The CDFX reader shall tolerate and ignore writer- or
  tool-identification notes — including leading or embedded XML comments such
  as `Created with CANape … CDF 2.0 Writer` — emitted by any producing tool,
  treating them as non-significant content and not as a parse error or a
  `ValidationIssue`.
- **Rationale (informative):** production `.cdfx` files in the
  Vector-CANape-dominated ecosystem carry a tool-identification note
  (`design-input/cdfx-research.md` §2.1); the reader must accept files from
  CANape, s19_app or any other tool without flagging that note.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A `.cdfx` carrying a leading `Created with …` XML comment reads every
    `SW-INSTANCE` and emits no comment-related issue.

### LLR-006.8 — Read-path size and nesting-depth bound
- **Traceability:** HLR-006
- **Statement:** Before parsing, the CDFX reader shall reject any `.cdfx` whose
  on-disk byte size exceeds the documented cap of **256 MB**
  (`DEFAULT_COPY_SIZE_CAP_BYTES`) by emitting exactly one `ValidationIssue`
  with code `R-XML-PARSE` and returning an empty change-list without raising an
  exception; and the reader shall bound XML element nesting depth, surfacing a
  document that exceeds the depth bound as one `R-XML-PARSE` issue rather than
  by unbounded recursion or memory growth.
- **Rationale (informative):** LLR-006.6 covers entity-expansion payloads but
  not a plain, well-formed but **huge** `.cdfx`: `ElementTree.parse` builds the
  entire DOM in memory, so a multi-gigabyte well-formed file exhausts memory
  with no malformed XML and no entity payload (S-003). The 256 MB cap reuses
  the `workspace.py` `DEFAULT_COPY_SIZE_CAP_BYTES` rationale already applied to
  every other file the app ingests — keeping one consistent ingest cap rather
  than inventing a new number. The size check is performed **before** parsing
  so an oversized file is never loaded into memory at all. The nesting-depth
  bound caps the second resource-exhaustion vector (deeply nested elements)
  that the byte cap alone does not address.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A `.cdfx` larger than 256 MB produces exactly one `R-XML-PARSE` issue, an
    empty change-list, and is not parsed into memory.
  - A `.cdfx` whose element nesting exceeds the depth bound produces one
    `R-XML-PARSE` issue with no unbounded recursion.

### LLR-007.1 — Patch Editor renders the change-list
- **Traceability:** HLR-007
- **Statement:** The Patch Editor screen shall render the current change-list
  as a row per entry showing the parameter name, array index, displayed value,
  and resolution status, replacing the static placeholder hex panes of the
  inert shell.
- **Validation:** test (integration)
- **Acceptance criteria (informative):**
  - Adding an entry adds a visible row; the deferral notice for change-list
    editing is removed.

### LLR-007.2 — Patch Editor add/edit/remove controls are wired
- **Traceability:** HLR-007
- **Statement:** The Patch Editor screen shall wire its parameter-name, index
  and value inputs to the change-list model's add, edit and remove operations,
  replacing the inert inputs of `R-TUI-027`.
- **Validation:** test (integration)
- **Acceptance criteria (informative):**
  - Submitting the inputs mutates the change-list and updates the rendered
    rows.

### LLR-007.3 — Patch Editor save action writes a `.cdfx`
- **Traceability:** HLR-007, HLR-004
- **Statement:** When the engineer triggers the Patch Editor save action, the
  screen shall invoke the CDFX writer to produce a `.cdfx` file inside
  `.s19tool/workarea/` through the work-area-contained write path of LLR-007.7
  and shall surface the write's `ValidationIssue` results via the existing
  status path.
- **Validation:** test (integration)
- **Acceptance criteria (informative):**
  - The save action produces a `.cdfx` file under `.s19tool/workarea/` and
    reports any write issues.

### LLR-007.4 — Patch Editor load action reads a `.cdfx`
- **Traceability:** HLR-007, HLR-005
- **Statement:** When the engineer triggers the Patch Editor load action with a
  `.cdfx` path, the screen shall invoke the CDFX reader through the
  path-resolving load path of LLR-005.5, shall populate the change-list from
  the parsed entries, and shall surface the read's `ValidationIssue` results.
- **Validation:** test (integration)
- **Acceptance criteria (informative):**
  - Loading a valid `.cdfx` populates visible change-list rows.
  - Read issues are surfaced, load does not crash on a malformed file.

### LLR-007.5 — CDFX handler logic lives outside `app.py`
- **Traceability:** HLR-007, (constraint C-8)
- **Statement:** The CDFX read/write and change-list model logic shall reside
  in a dedicated module (service-style), and `app.py` shall contain only the
  UI-state wiring that calls it.
- **Validation:** inspection
- **Acceptance criteria (informative):**
  - No XML parsing/serialization code is added to `app.py`.

### LLR-007.6 — Empty-state preserved when no change-list exists
- **Traceability:** HLR-007
- **Statement:** While the Patch Editor is open with an empty change-list, the
  screen shall display a single neutral empty-state line in place of the
  change-list rows — a non-error, non-warning prompt instructing the engineer
  to add a change-list entry or load a `.cdfx` file — and shall not display a
  blank pane, a placeholder error, or a stack trace.
- **Rationale (informative):** This restates the empty-state requirement
  self-containedly so a reader of this document alone knows what the bar must
  contain. It remains consistent with the batch-02 empty-state pattern of
  `R-TUI-030`, kept here as an informative cross-reference only (A-08).
- **Validation:** test (integration)
- **Acceptance criteria (informative):**
  - An empty Patch Editor shows the neutral add-or-load prompt line, not a
    blank pane or error.

### LLR-007.7 — CDFX write target is work-area-contained
- **Traceability:** HLR-007, HLR-004
- **Statement:** The CDFX write path shall resolve and containment-validate its
  target the same way `s19_app/tui/workspace.py` `copy_into_workarea` does —
  reusing the existing `workspace.py` helpers (`copy_into_workarea` /
  `_path_traverses_reparse_point`), not a re-implementation: the resolved
  target shall lie under a `.s19tool/workarea/` root; a target that is, or
  whose traversed parents include, a symbolic link or NTFS reparse point shall
  be rejected; and a target whose name already exists shall be dedup-suffixed
  (`_<N>` before the suffix) or explicitly confirmed before any overwrite. A
  containment, reparse-point, or overwrite rejection shall be surfaced as a
  write-side `ValidationIssue` rather than an uncaught exception.
- **Rationale (informative):** A-6 / OQ-3 scoped `.cdfx` out of
  `validate_project_files`, removing the containment guarantee that gate
  provided; this LLR **replaces** that guarantee rather than leaving the write
  path unconstrained (S-001). The product decision (DD-10) is to save `.cdfx`
  files into `.s19tool/workarea/` under the existing, already-hardened
  `workspace.py` containment guards — consistent with the app's model, where
  the work area is the home of every other on-disk artifact and an "open work
  area" action already exists. `Path.resolve` alone is not sufficient on
  Windows because it silently follows junctions, which is why the explicit
  `_path_traverses_reparse_point` walk is reused rather than re-derived. No new
  write path is introduced.
- **Validation:** test (integration)
- **Acceptance criteria (informative):**
  - A save produces a `.cdfx` whose resolved path is under `.s19tool/workarea/`.
  - A write target that traverses a symlink / junction is rejected with a
    `ValidationIssue`, not a crash.
  - A save onto an existing filename produces a dedup-suffixed file (or a
    confirmed overwrite), never a silent clobber.

### LLR-008.1 — Name cross-check against the loaded A2L
- **Traceability:** HLR-008
- **Statement:** When a `.cdfx` file is loaded while an A2L is loaded, the CDFX
  reader shall, for each `SW-INSTANCE` whose name matches no A2L parameter,
  emit one warning-level `ValidationIssue` with code `R-NAME-NOT-IN-A2L`.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - An instance named for a non-existent A2L parameter yields one
    `R-NAME-NOT-IN-A2L` warning.

### LLR-008.2 — Array-length cross-check against the loaded A2L
- **Traceability:** HLR-008
- **Statement:** When a `.cdfx` file is loaded while an A2L is loaded, the CDFX
  reader shall, for each array `SW-INSTANCE` whose `V` count differs from the
  A2L `element_count` of the matched parameter, emit one warning-level
  `ValidationIssue` with code `R-ARRAY-LEN-MISMATCH`.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - A 4-element array instance against a 3-element A2L parameter yields one
    `R-ARRAY-LEN-MISMATCH` warning.

### LLR-008.3 — Cross-check skipped without an A2L
- **Traceability:** HLR-008
- **Statement:** While no A2L is loaded, the CDFX reader shall not emit
  `R-NAME-NOT-IN-A2L` or `R-ARRAY-LEN-MISMATCH` issues and shall still parse
  the `.cdfx` file into change-list entries.
- **Validation:** test (unit)
- **Acceptance criteria (informative):**
  - Loading a `.cdfx` with no A2L produces entries and no cross-check issues.

---

## 5. Validation Strategy

> Owned by the qa-reviewer pass. This section assigns a validation method to
> every HLR and LLR, defines the `TC-NNN` test cases with bidirectional
> traceability, specifies the synthetic `.cdfx` fixtures, records the
> round-trip and security-test approach, flags weakly-testable requirements,
> and states the batch acceptance criteria. The architect's per-HLR
> `Validation` field (Section 3) was treated as input; the method assignment
> below is authoritative for Phases 2–4. The CDFX rule codes `W-*` / `R-*` of
> `design-input/cdfx-research.md` §7 are the basis for the read/write rule
> test cases.

### 5.1 Methods

- **test** — automated execution under `pytest`. The default for every LLR.
  Three sub-kinds are used:
  - **test (unit)** — exercises a function/class of the change-list model or
    the CDFX read/write module directly, with synthetic in-memory or
    `tmp_path` inputs. No Textual app instance.
  - **test (integration)** — drives the Patch Editor through a real
    `S19TuiApp` instance headlessly via `App.run_test()` and the Textual
    `pilot`, the established harness pattern of `tests/test_tui_directionb.py`.
  - **test (round-trip)** — a unit test whose verdict is structural equality
    between a change-list and the change-list recovered after a
    write→read cycle. Called out separately because it is the strongest
    correctness check (see §5.4).
- **demo** — observed execution of behavior. Used to corroborate the two
  UX-oriented HLRs (HLR-003 value display, HLR-007 functional screen); the
  demo script is produced in Phase 6, not a pass/fail gate.
- **inspection** — static review of code against a written checklist. Used
  only where there is no objective runtime assertion: LLR-007.5 (the
  module-placement constraint C-8). The inspection checklist is inline in
  §5.6 so the verdict is not reviewer-subjective.
- **analysis** — quantitative/structural reasoning. Used to corroborate the
  XML-safety test cases TC-027a / TC-027b (the `DOCTYPE`/entity-rejection
  argument) and to record the writer-cannot-provoke fact for the un-provokable
  `W-*` invariant sub-cases TC-019a/b/c/g — see §5.5 and §5.8.

A single requirement may carry a primary method plus a corroborating method;
the per-requirement table (§5.2 / §5.3) lists both.

### 5.2 Per-HLR validation-method table

| Requirement | Primary | Corroborating | Test Case ID(s) | Notes |
|-------------|---------|---------------|-----------------|-------|
| HLR-001 — Parameter change-list model | test | — | TC-001, TC-002, TC-003 | Add/edit/remove, identity de-duplication and deterministic ordering are model-level facts assertable in unit tests. |
| HLR-002 — Parameter resolution against the loaded A2L | test | — | TC-004, TC-005, TC-006, TC-007 | Resolution outcomes (resolved / unresolved / index-out-of-range / unresolved-no-a2l) are discrete, assertable states. |
| HLR-003 — Value entry and type-driven display format | test | demo | TC-008, TC-009, TC-010 | Display-form selection per A2L data type is a deterministic mapping; demo corroborates that the rendered forms read naturally. |
| HLR-004 — CDFX write | test | test (round-trip) | TC-011, TC-012, TC-013, TC-014, TC-032, TC-033, TC-038, TC-024 | The produced `.cdfx` structure is asserted element-by-element; TC-014 also covers the tool-identification note, TC-032 the dedicated note check, TC-033 round-trip-safe floats, TC-038 the array-coalescing + sparse-array rejection; TC-024 round-trip corroborates write correctness end-to-end. |
| HLR-005 — CDFX read | test | test (round-trip) | TC-015, TC-016, TC-017, TC-034, TC-018, TC-039, TC-024, TC-037 | Parsing valid and malformed `.cdfx` are both assertable; TC-017/TC-034 cover producer / tool-note tolerance; TC-039 covers `VAL_BLK` expansion; TC-037 covers load-path resolution; TC-024 round-trip corroborates read correctness. |
| HLR-006 — CDFX validation rule set | test | — | TC-019a…TC-019h, TC-020, TC-021, TC-022, TC-023, TC-027a, TC-027b, TC-035, TC-036, TC-034, TC-038 | Each `W-*` / `R-*` rule code is provoked by a crafted fixture and asserted with its documented code and severity; TC-019a…TC-019h are the per-`W-*`-rule sub-cases; TC-038 covers the `W-ARRAY-SPARSE` writer-behavior code; TC-027a/TC-027b cover the entity / DOCTYPE rejection rule; TC-035 the read-path size / depth bound; TC-034 the tool-note tolerance. |
| HLR-007 — Functional Patch Editor screen | test | demo | TC-025, TC-026, TC-027a, TC-028 | The screen build/edit/save/load behavior is driven via `App.run_test()`; TC-027a is the integration arm that drives the load action with a malicious `.cdfx`; demo corroborates the screen is a working tool, not a shell. |
| HLR-008 — Cross-check of a loaded `.cdfx` against the A2L | test | — | TC-029, TC-030, TC-031 | Name and array-length cross-check warnings, and their suppression with no A2L, are assertable. |

### 5.3 Per-LLR validation-method table

| Requirement | Method | Test Case ID(s) | Notes |
|-------------|--------|-----------------|-------|
| LLR-001.1 — Change-list entry data structure | test (unit) | TC-001 | Entry holds `parameter_name` / `array_index` (`Optional[int]`) / `value` / resolution-status; a scalar/string entry has `array_index is None`, an array-element entry an integer index. |
| LLR-001.2 — Add / edit / remove operations | test (unit) | TC-002 | Add-then-remove leaves the list empty; edit mutates only the targeted entry. |
| LLR-001.3 — Entry identity and duplicate handling | test (unit) | TC-002 | Adding `(name, index)` twice updates in place — one entry, latest value. |
| LLR-001.4 — Change-list ordering is deterministic | test (unit) | TC-003 | Two serializations of the same change-list produce identical `SW-INSTANCE` order. |
| LLR-002.1 — Resolve a parameter against the loaded A2L | test (unit) | TC-004 | A name present in the synthetic A2L resolves with its datatype; resolution calls into `tui/a2l.py`, no A2L re-parse. |
| LLR-002.2 — Unresolved-name handling | test (unit) | TC-005 | An unknown name yields an `unresolved` entry, no exception. |
| LLR-002.3 — Array-index range check | test (unit) | TC-006 | Integer index 5 on a 3-element array parameter is `index-out-of-range`; a scalar entry (`array_index is None`) against a scalar A2L parameter (`element_count==1`) resolves and is not range-checked. |
| LLR-002.4 — Resolution without a loaded A2L | test (unit) | TC-007 | With no A2L, every entry is `unresolved-no-a2l`, no exception. |
| LLR-003.1 — Display-format selection from A2L data type | test (unit) | TC-008 | `UBYTE` 23 → `23` / `0x17`; negative `SWORD` signed; `FLOAT32_IEEE` / `FLOAT16_IEEE` fractional; large `A_UINT64` near `2**64-1` decimal + hex; ASCII quoted. |
| LLR-003.2 — Display-format fallback for unresolved entries | test (unit) | TC-009 | An unresolved entry's value renders as plain decimal, no exception. |
| LLR-003.3 — Value entry is stored as a physical value | test (unit) | TC-010 | Stored value equals the entered physical value regardless of display form. |
| LLR-004.1 — CDFX writer emits the CDF 2.0 backbone | test (unit) | TC-011 | Root `MSRSW`, `CATEGORY=CDF20`, the `SW-SYSTEMS…SW-INSTANCE-TREE` chain with `SHORT-NAME`s. |
| LLR-004.2 — One `SW-INSTANCE` per resolved parameter | test (unit) | TC-012 | Scalar entry → `SW-INSTANCE` with `CATEGORY=VALUE`; instance `SHORT-NAME` equals the parameter name; exactly one `SW-INSTANCE` per distinct resolved `parameter_name`, not one per change-list entry — three array-element entries of one name yield one instance (coalescing detailed in TC-038). |
| LLR-004.3 — CDFX writer encodes scalar and array values | test (unit) | TC-013 | Scalar → one `V`; 3-element array → `VG` with three positional `V`; string → one `VT`. |
| LLR-004.4 — Writer output is well-formed UTF-8 XML | test (unit) | TC-014 | The written file re-parses via `ElementTree` without exception; XML declaration present. |
| LLR-004.5 — Unresolved entries excluded with a warning | test (unit) | TC-019d | An unresolved entry produces no `SW-INSTANCE` and one warning `ValidationIssue`; a valid sibling entry is still written. |
| LLR-004.6 — Empty-change-list write is reported | test (unit) | TC-019h | A literally-empty change-list and an all-unresolved change-list each yield a valid backbone-only `MSRSW` file plus one `W-EMPTY-CHANGELIST` warning. |
| LLR-004.7 — CDFX writer emits a tool-identification note | test (unit) | TC-014, TC-032 | The written `.cdfx` carries a leading `Created with s19_app CDF 2.0 Writer` XML comment and still re-parses via `ElementTree`; TC-032 is the dedicated check. |
| LLR-004.8 — CDFX writer emits round-trip-safe float values | test (unit) | TC-033, TC-024 | A float written then re-read compares exactly equal with no tolerance; TC-033 is the dedicated unit check, TC-024 corroborates end-to-end. |
| LLR-004.9 — Writer coalesces array-element entries into one `SW-INSTANCE` | test (unit), test (round-trip) | TC-038, TC-024 | Array-element entries sharing a `parameter_name` coalesce into one `VAL_BLK` `SW-INSTANCE` with one ascending-`array_index` `VG`; a sparse / non-zero-based array group is rejected as one `W-ARRAY-SPARSE` warning with no `SW-INSTANCE` and no synthesized value; TC-024 corroborates the coalesce→expand round-trip. |
| LLR-005.1 — Reader parses well-formed files into entries | test (unit), test (round-trip) | TC-015, TC-024 | A writer-produced file parses back to an equivalent change-list (TC-024 is the round-trip verdict). |
| LLR-005.2 — Reader tolerates malformed XML | test (unit) | TC-016 | A truncated/garbage file → one `R-XML-PARSE` error issue, empty change-list, no crash. |
| LLR-005.3 — Reader tolerates producer-specific variation | test (unit) | TC-017 | A file with `ADMIN-DATA` / `SW-CS-HISTORY` / `SW-CS-FLAGS` siblings and an `xmlns` still reads all instances. |
| LLR-005.4 — Reader decodes numeric value notations | test (unit) | TC-018 | `<V>0x17</V>`→23, `<V>1.5e1</V>`→15.0, decimal decode; `0b101`→5 is asserted only as a tolerant-superset case, not a normative requirement (OQ-7). |
| LLR-005.5 — CDFX load path resolves the user-supplied path | test (unit) | TC-037 | A valid `.cdfx` path is resolved via `resolve_input_path`; an unresolvable path yields exactly one `R-XML-PARSE` issue and no file is opened. |
| LLR-005.6 — Reader expands a `VAL_BLK` instance into array-element entries | test (unit), test (round-trip) | TC-039, TC-024 | A `VAL_BLK` `SW-INSTANCE` with an N-`V` `VG` expands to N entries `(name, 0…N-1)`; a `VALUE`/`BOOLEAN` instance → one scalar entry (`array_index=None`); an `ASCII` instance → one string entry (`array_index=None`); TC-024 corroborates the coalesce→expand round-trip. |
| LLR-006.1 — Write-time validation rule set | test (unit), analysis | TC-019a…TC-019h, TC-038, TC-022 | Each of the eight `W-*` structural codes has its own sub-case TC-019a…TC-019h; the two writer-behavior codes `W-INSTANCE-EXCLUDED` (TC-019d) and `W-ARRAY-SPARSE` (TC-038) are exercised through the real writer. The `W-*` validator is exercised as a standalone function fed crafted element trees (not only via the real writer). `W-XML-WELLFORMED`, `W-ROOT-MSRSW`, `W-BACKBONE`, `W-CATEGORY-VALUE-CONSISTENT` are correct-writer invariants — their negative sub-cases feed the standalone validator a deliberately-broken tree; where no fault can be injected even into the validator, the row is marked `analysis` / `inspection`. |
| LLR-006.2 — Read-time validation rule set | test (unit) | TC-020, TC-021, TC-023 | Each `R-*` code (`R-XML-PARSE`, `R-ROOT-MSRSW`, `R-VERSION-UNKNOWN`, `R-BACKBONE-MISSING`, `R-INSTANCE-NO-NAME`, `R-INSTANCE-NO-VALUE`, `R-CATEGORY-UNSUPPORTED`, `R-CATEGORY-VALUE-MISMATCH`, `R-VALUE-NOT-NUMERIC`) is provoked and asserted. |
| LLR-006.3 — Issues reuse the project ValidationIssue model | test (unit) | TC-022 | Every CDFX finding is a `ValidationIssue` with `artifact="cdfx"`; severity round-trips through `color_policy.css_class_for_severity` to a valid `sev-*` class. |
| LLR-006.4 — Version-token tolerance on read | test (unit) | TC-021 | A `CDF21` file reads its instances and produces exactly one `R-VERSION-UNKNOWN` info issue. |
| LLR-006.5 — Unsupported instance categories are read-only, not fatal | test (unit) | TC-023 | A `MAP` instance loads as a read-only entry with one `R-CATEGORY-UNSUPPORTED` warning, no exception. |
| LLR-006.6 — XML entity / DOCTYPE rejection on read | test (unit) | TC-027a, TC-027b | A `.cdfx` containing a `DOCTYPE` / `<!ENTITY>` declaration is rejected as exactly one `R-XML-PARSE` issue with an empty change-list and no entity ever expanded; TC-027a is the billion-laughs (internal-entity) fixture, TC-027b the external-entity (`SYSTEM`) fixture. |
| LLR-006.7 — Reader tolerates writer / tool-identification notes | test (unit) | TC-017, TC-034 | A `.cdfx` carrying a leading `Created with …` XML comment reads every `SW-INSTANCE` with zero comment-related issues; TC-034 is the dedicated check. |
| LLR-006.8 — Read-path size and nesting-depth bound | test (unit) | TC-035 | A `.cdfx` over the 256 MB cap is rejected (as one `R-XML-PARSE` issue) before parsing; a document exceeding the nesting-depth bound yields one `R-XML-PARSE` issue with no unbounded recursion. |
| LLR-007.1 — Patch Editor renders the change-list | test (integration) | TC-025 | Adding an entry adds a visible row; the `R-TUI-027` deferral notice is gone. |
| LLR-007.2 — Add/edit/remove controls are wired | test (integration) | TC-025 | Submitting the name/index/value inputs mutates the change-list and re-renders the rows. |
| LLR-007.3 — Save action writes a `.cdfx` | test (integration) | TC-026 | The save action produces a `.cdfx` in the work area and surfaces write issues via the status path. |
| LLR-007.4 — Load action reads a `.cdfx` | test (integration) | TC-026, TC-027a | Loading a valid `.cdfx` populates visible rows; loading a malformed / malicious one surfaces issues and does not crash. |
| LLR-007.5 — CDFX handler logic lives outside `app.py` | inspection | TC-028 | No XML parse/serialize code in `app.py`; the handler is a dedicated service-style module — checklist in §5.6. |
| LLR-007.6 — Empty-state preserved when no change-list exists | test (integration) | TC-025 | An empty Patch Editor shows a neutral prompt, not a blank pane or error. |
| LLR-007.7 — CDFX write target is work-area-contained | test (integration) | TC-036 | A saved `.cdfx` resolves under `.s19tool/workarea/`; a reparse-point traversal target is rejected with a `ValidationIssue`; an existing-filename save dedup-suffixes with no silent clobber. |
| LLR-008.1 — Name cross-check against the loaded A2L | test (unit) | TC-029 | An instance named for a non-existent A2L parameter yields one `R-NAME-NOT-IN-A2L` warning. |
| LLR-008.2 — Array-length cross-check against the loaded A2L | test (unit) | TC-030 | A 4-element array instance against a 3-element A2L parameter yields one `R-ARRAY-LEN-MISMATCH` warning. |
| LLR-008.3 — Cross-check skipped without an A2L | test (unit) | TC-031 | Loading a `.cdfx` with no A2L produces entries and zero cross-check issues. |

### 5.4 Test fixtures — synthetic `.cdfx` data only

Per constraint C-9 and `R-TUI-034`, every `.cdfx`, A2L and change-list fixture
is **synthetic** — generated in-test or via `tests/conftest.py`-style
generators. No client firmware / A2L / CDFX artifact is used. The new fixture
set, to live in `tests/conftest.py` alongside the existing
`make_large_s19/a2l/mac` generators and following the same style (`seed:int=0`
default, programmatic content, no static binary files on disk):

| Fixture / generator | Produces | Used by |
|---------------------|----------|---------|
| `make_minimal_cdfx` | A well-formed CDF 2.0 `.cdfx` carrying one `VALUE`, one `VAL_BLK` (a multi-`V` `VG`) and one `ASCII` `SW-INSTANCE` — the §5 minimal example of the research doc. | TC-015, TC-018, TC-037, TC-039 |
| `make_malformed_cdfx` | A truncated / non-well-formed XML byte stream. | TC-016 |
| `make_variant_cdfx` | A valid `.cdfx` with extra optional siblings (`ADMIN-DATA`, `SW-CS-HISTORY`, `SW-CS-FLAGS`) and a declared `xmlns`. | TC-017 |
| `make_tool_note_cdfx` | A valid CDF 2.0 `.cdfx` (the `make_minimal_cdfx` shape) carrying a leading `Created with …` writer / tool-identification XML comment. | TC-017, TC-034 |
| `make_rule_violation_cdfx` | A parametrized generator emitting one `.cdfx` per `R-*` read rule, each crafted to trip exactly that rule (missing root, missing backbone, nameless instance, valueless instance, `MAP` category, value-count mismatch, non-numeric `V`, `CDF21` token). **Every fixture variant also carries one valid `SW-INSTANCE` alongside the violating element**, so TC-020 can assert the valid sibling is still recovered (the collect-don't-abort intent). | TC-020, TC-021, TC-023 |
| `make_billion_laughs_cdfx` | A `.cdfx` carrying a `DOCTYPE` with nested internal `<!ENTITY>` declarations (the classic billion-laughs amplification payload) and **no** `SYSTEM`/`PUBLIC` reference — one attack vector only. | TC-027a |
| `make_external_entity_cdfx` | A `.cdfx` carrying a `DOCTYPE` with a single external `<!ENTITY>` declaration whose `SYSTEM` reference points at a **sentinel temp file of known unique content** created by the test — one attack vector only. The known content lets TC-027b assert that string is **absent** from the parsed result, i.e. the external file was never read. | TC-027b |
| `make_oversized_cdfx` | A `.cdfx` whose reported on-disk size exceeds the 256 MB `DEFAULT_COPY_SIZE_CAP_BYTES` cap, plus a deeply-nested variant exceeding the element nesting-depth bound. The fixture **need not write a real 256 MB file**: it exposes a **size-probe seam** — the reader obtains the candidate's byte size through an injectable size-probe (e.g. a `size_probe` callable defaulting to `Path.stat().st_size`) which the test substitutes with a stub returning an over-cap value, so the size-reject path is exercised against a small on-disk file and the test stays fast. | TC-035 |
| `make_patch_a2l` | A small synthetic A2L (reusing the `_a2l_characteristic_block` style) with named scalar, 1-D array (`element_count` 3) and ASCII characteristics, for resolution and cross-check tests. | TC-004…TC-007, TC-029, TC-030 |
| `change_list_factory` | An in-memory change-list builder producing resolved scalar + array + string entries plus unresolved/out-of-range entries on demand; **array parameters are built as the per-element `(name, k)` entry set** the LLR-001.1 model uses (`array_index` integer), and a scalar/string entry carries `array_index = None`. It yields **adversarial IEEE float entries** — `0.1`, a denormal (e.g. `5e-324`), and a 17-significant-digit value — for the float round-trip tests, and **a sparse array group** (entries for index 0 and 2 but not 1, and a group whose lowest index is 1) for the LLR-004.9 `W-ARRAY-SPARSE` rejection test. | TC-001…TC-003, TC-011…TC-014, TC-019a…TC-019h, TC-024, TC-033, TC-038 |

**Optional supplementary fixture.** The research doc cites no downloadable
sample `.cdfx`; §9 lists only specification and vendor-documentation URLs. If a
public CDF 2.0 sample (for example one shipped with the MathWorks Vehicle
Network Toolbox documentation, research §9) can be obtained under a
redistributable license, it may be added as a single read-only supplementary
fixture for TC-017 to harden the producer-variation case against real-world
output. This is **optional and not a blocker** — RK-1 (no client sample)
remains an accepted residual risk until then.

### 5.5 Round-trip and XML-security test approach

**Round-trip (TC-024) — the strongest correctness test.** TC-024 builds a
change-list with at least one resolved scalar, one 1-D array and one ASCII
entry via `change_list_factory`, writes it to a `tmp_path` `.cdfx` with the
CDFX writer, reads that file back with the CDFX reader, and asserts the
recovered change-list is **structurally equal** to the original: same set of
`(parameter_name, array_index)` keys, same per-entry values, same category,
same deterministic order (LLR-001.4). Per LLR-004.8 (resolution of OQ-6) the
writer emits IEEE float `V` text at full `repr()`-precision, so the value
assertion is **exact equality (`==`) with no float tolerance** — including for
IEEE float values; an inexact write→read cycle is therefore itself a defect
this test catches, not noise the oracle must absorb. Any write defect that
produces an unparseable, mis-shaped or value-losing `SW-INSTANCE`, and any
read defect that drops or mis-decodes an instance, fails this single
assertion. TC-024 is the corroborating verdict for HLR-004 and HLR-005, the
primary verdict for LLR-005.1, and the end-to-end corroboration for LLR-004.8
(its dedicated unit check is TC-033).

**In-memory value type — pinned (Q-03).** For the round-trip oracle to be able
to *fail*, the value model and the writer representation are pinned. A
change-list entry's numeric `value`, when the resolved parameter is an IEEE
float, is held as a Python `float` — IEEE-754 binary64. The writer emits that
binary64 as text equivalent to Python `repr()` of the float (DD-8 / LLR-004.8),
which is the shortest decimal string that round-trips binary64 exactly. A
writer that instead reduced precision — `str()` on an older Python, `%g`,
`%.6f`, or any fixed-width format — would lose bits on values whose shortest
exact decimal is long. The float fixtures of `change_list_factory` are
therefore **adversarial by construction**: `0.1` (no exact binary64 decimal of
modest length under naive formatting), a denormal such as `5e-324` (smallest
positive binary64, which a fixed-width format truncates to `0.0`), and a
17-significant-digit value (the maximum binary64 needs). TC-024 and TC-033
assert exact `==` on the round-tripped value of each — a lossy representation
fails at least one of the three, so the round-trip test is no longer
tautological: it can genuinely fail if the writer drops to a lossy format.

**XML security (TC-027a / TC-027b) — DOCTYPE / entity rejection.** Phase 1
flagged that parsing external `.cdfx` with `xml.etree.ElementTree` exposes the
reader to XML entity-expansion ("billion-laughs") amplification and
external-entity (`SYSTEM`) resolution. **LLR-006.6 (rewritten in iteration 3)**
now mandates the concrete, deterministic, stdlib-only defense: the reader
**rejects any `.cdfx` containing a `DOCTYPE` or `<!ENTITY>` declaration** via an
`xml.etree.ElementTree.XMLParser` whose DTD / entity-declaration handler raises
on the first such declaration (DD-9). The single overloaded TC-027 of earlier
drafts is **split into two single-vector test cases** (resolution of Q-02,
Q-06, S-004, S-005):

- **TC-027a — billion-laughs (internal-entity) fixture.** Feeds
  `make_billion_laughs_cdfx` — a `DOCTYPE` with nested internal `<!ENTITY>`
  declarations, no `SYSTEM` reference — to the CDFX reader. Deterministic
  assertion: the `DOCTYPE` is present, the reader surfaces **exactly one**
  `R-XML-PARSE` `ValidationIssue`, the returned change-list is **empty**, and
  the parser **never expands an entity** (the DTD handler raises before any
  entity declaration is processed — assertable because no nested-entity text
  appears in any parsed node and no `ValidationIssue` message echoes expanded
  content). Because the verdict is the deterministic presence of the `DOCTYPE`
  rejection — not "did it finish in time" — the `pytest` timeout is kept
  **only as defense-in-depth**, not as the primary assertion (closes S-005). An
  integration arm drives the same fixture through the Patch Editor load action
  and asserts the screen stays usable.
- **TC-027b — external-entity (`SYSTEM`) fixture.** Feeds
  `make_external_entity_cdfx`, whose external `<!ENTITY>` `SYSTEM` reference
  points at a **sentinel temp file** the test creates with a known unique
  content string. Deterministic assertion: the reader surfaces **exactly one**
  `R-XML-PARSE` `ValidationIssue`, the returned change-list is empty, and — the
  concrete no-external-read check — the sentinel string is **absent** from
  every parsed value, every entry field, and every `ValidationIssue` message,
  proving the external file was never read and inlined.

The *analysis* corroboration records that `DOCTYPE`-rejection neutralizes both
vectors with one rule and that no `defusedxml` (or other) dependency is
introduced (C-2, DD-9). **Both test cases are reviewed by the Phase 2
security-reviewer**; they are the validation hook for LLR-006.6.

**Read-path size / depth bound (TC-035).** TC-035 covers LLR-006.8 — the
plain-but-huge and deeply-nested resource-exhaustion vectors the entity defense
does not address. It uses `make_oversized_cdfx` and the fixture's
**size-probe seam**: the test substitutes the reader's injectable size-probe
with a stub reporting an over-cap byte size, so a small on-disk file exercises
the pre-parse size-reject path without writing a real 256 MB file. The
assertion is deterministic — an over-cap probe yields exactly one `R-XML-PARSE`
issue, an empty change-list, and `ElementTree.parse` is **never reached** (the
size check precedes it). A second arm feeds the deeply-nested variant and
asserts one `R-XML-PARSE` issue with no unbounded recursion.

### 5.6 Inspection checklist (LLR-007.5 → TC-028)

TC-028 is a static-review test case. Pass requires **all** of:
- [ ] CDFX read, CDFX write and the change-list model live in a dedicated
      module (service-style), not in `app.py` — consistent with constraint
      C-8 and DD-6.
- [ ] No `xml.etree.ElementTree` import and no XML parse/serialize call appear
      in `app.py`; `app.py` holds only UI-state wiring that calls the handler.
- [ ] New public functions carry the `PROJECT_RULES.md` docstring section
      order (Summary→Args→Returns→Raises→Data Flow→Dependencies→Example) and
      type hints (constraint C-4) — spot-checked, not exhaustively.
- [ ] No new runtime dependency added to `pyproject.toml` (constraint C-2);
      `requirements.txt` unchanged.

### 5.7 Test-case catalogue and traceability

> Every LLR maps to ≥1 TC; every HLR maps to its decomposed LLRs' TCs.
> "Method" abbreviations: U = test (unit), I = test (integration),
> RT = test (round-trip), INSP = inspection, analysis = analysis (used as a
> corroborating method only — see §5.1). A cell listing two methods (e.g.
> `U, analysis`) carries a primary plus a corroborating method.

| TC | Title | Method | Covers LLR | Parent HLR | Expected result |
|----|-------|--------|------------|------------|-----------------|
| TC-001 | Change-list entry construction | U | LLR-001.1, LLR-001.3 | HLR-001 | An entry built with name+index reports its four fields; a scalar entry and an ASCII entry each have `array_index is None`; an array-element entry has an integer `array_index`; `(name, None)` and `(name, 0)` are distinct identities. |
| TC-002 | Add / edit / remove and identity de-duplication | U | LLR-001.2, LLR-001.3 | HLR-001 | Add-then-remove of one key leaves the list empty; editing changes only the targeted entry; adding `PARAM[0]` twice yields one entry with the latest value. |
| TC-003 | Deterministic change-list ordering | U | LLR-001.4 | HLR-001 | Two writes of the same change-list produce byte-identical `SW-INSTANCE` order. |
| TC-004 | Resolve a known parameter against the A2L | U | LLR-002.1 | HLR-002 | A name in the synthetic A2L resolves with its `datatype`, `element_count` and section; the resolver delegates to `tui/a2l.py` and does not re-parse A2L text. |
| TC-005 | Unresolved-name handling | U | LLR-002.2 | HLR-002 | An unknown name produces an `unresolved` entry; no exception; the list stays usable. |
| TC-006 | Array-index range check | U | LLR-002.3 | HLR-002 | Integer index 5 on a 3-element array parameter is flagged `index-out-of-range`; a scalar entry (`array_index is None`) against a scalar A2L parameter (`element_count==1`) resolves normally and is not range-checked. |
| TC-007 | Resolution without a loaded A2L | U | LLR-002.4 | HLR-002 | With no A2L loaded, every entry is `unresolved-no-a2l`; no exception. |
| TC-008 | Type-driven display-format selection | U | LLR-003.1 | HLR-003 | `UBYTE` 23 → `23` / `0x17`; a negative `SWORD` renders signed; `FLOAT32_IEEE` and `FLOAT16_IEEE` render with a fractional part; a large `A_UINT64` near `2**64-1` (above 2^53, where binary64 loses integer exactness) renders as decimal with an `0x` companion; an ASCII parameter renders as a quoted string. |
| TC-009 | Display-format fallback for unresolved entries | U | LLR-003.2 | HLR-003 | An unresolved entry's value renders as plain decimal text without error. |
| TC-010 | Physical value stored, display derived | U | LLR-003.3 | HLR-003 | The stored value equals the entered physical value; hex/ASCII rendering does not mutate it. |
| TC-011 | Writer emits the CDF 2.0 backbone | U | LLR-004.1 | HLR-004 | Output root tag is `MSRSW`; `CATEGORY` text is `CDF20`; the `SW-SYSTEMS→SW-SYSTEM→SW-INSTANCE-SPEC→SW-INSTANCE-TREE` chain is present, each container with a `SHORT-NAME`. |
| TC-012 | Writer emits one `SW-INSTANCE` per resolved parameter | U | LLR-004.2 | HLR-004 | A scalar entry yields a `SW-INSTANCE` with `CATEGORY=VALUE` and `SHORT-NAME` equal to the parameter name; exactly one `SW-INSTANCE` per distinct resolved `parameter_name` — three array-element entries of one name yield one instance, not three (detailed coalescing in TC-038). |
| TC-013 | Writer encodes scalar / array / string values | U | LLR-004.3 | HLR-004 | A scalar → one `V`; a 3-element array → a `VG` with three `V` children in index order; a string → one `VT`. |
| TC-014 | Writer output is well-formed UTF-8 XML with a tool note | U | LLR-004.4, LLR-004.7 | HLR-004 | The written file carries an XML declaration and re-parses via `ElementTree` without exception; it also carries a leading `Created with s19_app CDF 2.0 Writer` XML comment and remains well-formed with that comment present. |
| TC-015 | Reader parses a well-formed `.cdfx` into entries | U | LLR-005.1 | HLR-005 | `make_minimal_cdfx` parses to three change-list entries with correct names, categories and values. |
| TC-016 | Reader tolerates malformed XML | U | LLR-005.2 | HLR-005, HLR-006 | A truncated/garbage file → exactly one `R-XML-PARSE` error issue, an empty change-list, no exception raised. |
| TC-017 | Reader tolerates producer-specific variation | U | LLR-005.3, LLR-006.7 | HLR-005, HLR-006 | A `.cdfx` with `ADMIN-DATA` / `SW-CS-HISTORY` / `SW-CS-FLAGS` siblings, a declared `xmlns` and a leading `Created with …` tool-identification XML comment still reads every `SW-INSTANCE`, with zero comment-related issues. |
| TC-018 | Reader decodes numeric value notations | U | LLR-005.4 | HLR-005 | The normative cases decode: `<V>0x17</V>`→23, `<V>1.5e1</V>`→15.0, and plain decimal. `<V>0b101</V>`→5 is asserted as a **tolerant-superset** case only — A-07 dropped `0b` as a normative CDF binary form (OQ-7 open) — so a failure to decode `0b` is not a TC-018 failure; the assertion documents the tolerant acceptance, it does not require it. |
| TC-019a | `W-XML-WELLFORMED` — writer-output invariant | U, analysis | LLR-006.1 | HLR-006 | A correct writer cannot emit non-well-formed XML, so this code has no fault path through the real writer. The standalone `W-*` validator is fed a crafted non-well-formed element string and asserted to emit one `W-XML-WELLFORMED` issue with the documented severity; the writer-cannot-provoke fact is recorded by `analysis`. |
| TC-019b | `W-ROOT-MSRSW` — writer-output invariant | U, analysis | LLR-006.1 | HLR-006 | The standalone `W-*` validator is fed a crafted tree whose root tag is not `MSRSW` and asserted to emit one `W-ROOT-MSRSW` issue; the real writer cannot provoke it (`analysis`). |
| TC-019c | `W-BACKBONE` — writer-output invariant | U, analysis | LLR-006.1 | HLR-006 | The standalone `W-*` validator is fed a crafted tree missing the `SW-SYSTEMS…SW-INSTANCE-TREE` backbone and asserted to emit one `W-BACKBONE` issue; the real writer cannot provoke it (`analysis`). |
| TC-019d | `W-INSTANCE-NAME` + unresolved-exclusion | U | LLR-006.1, LLR-004.5 | HLR-004, HLR-006 | A change-list containing one unresolved/index-out-of-range entry **and one valid entry** is written: the unresolved entry produces no `SW-INSTANCE` and exactly one warning `ValidationIssue` with code `W-INSTANCE-EXCLUDED`, while the valid sibling is still written as a named `SW-INSTANCE` (the "others continue" intent). The standalone validator fed a `SW-INSTANCE` with an empty `SHORT-NAME` emits one `W-INSTANCE-NAME` issue. |
| TC-019e | `W-INSTANCE-CATEGORY` | U | LLR-006.1 | HLR-006 | The standalone `W-*` validator fed a `SW-INSTANCE` whose `CATEGORY` is outside the editable set (`VALUE`/`BOOLEAN`/`VAL_BLK`/`ASCII`) emits exactly one `W-INSTANCE-CATEGORY` issue with the documented severity. |
| TC-019f | `W-VALUE-PRESENT` | U | LLR-006.1 | HLR-006 | The standalone `W-*` validator fed a `SW-INSTANCE` with no `SW-VALUES-PHYS` value element emits exactly one `W-VALUE-PRESENT` issue. |
| TC-019g | `W-CATEGORY-VALUE-CONSISTENT` — writer-output invariant | U, analysis | LLR-006.1 | HLR-006 | A correct writer always emits a value shape matching the `CATEGORY`, so this code has no fault path through the real writer. The standalone `W-*` validator is fed a deliberately inconsistent tree (e.g. `CATEGORY=VALUE` carrying a `VG`) and asserted to emit one `W-CATEGORY-VALUE-CONSISTENT` issue; the writer-cannot-provoke fact is recorded by `analysis`. |
| TC-019h | `W-EMPTY-CHANGELIST` — empty and all-unresolved | U | LLR-006.1, LLR-004.6 | HLR-004, HLR-006 | A literally-empty change-list yields a valid backbone-only `MSRSW` file plus exactly one `W-EMPTY-CHANGELIST` warning. A two-entry all-unresolved change-list yields a valid backbone-only file plus two LLR-004.5 exclusion warnings **and** one `W-EMPTY-CHANGELIST` — three warnings total (LLR-004.6 zero-writable rule). |
| TC-020 | Read-time structural rule violations emit `R-*` issues | U | LLR-006.2 | HLR-006 | Each of `R-ROOT-MSRSW`, `R-BACKBONE-MISSING`, `R-INSTANCE-NO-NAME`, `R-INSTANCE-NO-VALUE`, `R-CATEGORY-VALUE-MISMATCH`, `R-VALUE-NOT-NUMERIC` is provoked by a crafted `make_rule_violation_cdfx` fixture and asserted with its documented code and severity; the load does not abort; **and** — because each fixture variant also carries one valid `SW-INSTANCE` alongside the violating element — the valid sibling instance is asserted to be recovered into the change-list, proving collect-don't-abort recovery rather than instance-tree abort (Q-04). |
| TC-021 | Version-token tolerance on read | U | LLR-006.2, LLR-006.4 | HLR-006 | A `CDF21` `.cdfx` reads its instances and produces exactly one `R-VERSION-UNKNOWN` info issue. |
| TC-022 | CDFX issues reuse the `ValidationIssue` model | U | LLR-006.3 | HLR-006 | Every CDFX finding is a `ValidationIssue` with `artifact == "cdfx"`; its severity round-trips through `css_class_for_severity` to a valid `sev-*` class. |
| TC-023 | Unsupported instance categories are read-only, not fatal | U | LLR-006.2, LLR-006.5 | HLR-006 | A `MAP` `SW-INSTANCE` loads as a read-only entry with exactly one `R-CATEGORY-UNSUPPORTED` warning; no exception. |
| TC-024 | CDFX round-trip — write then read recovers the change-list | RT | LLR-005.1, LLR-004.8, LLR-004.9, LLR-005.6 (+ HLR-004, HLR-005) | HLR-004, HLR-005 | A change-list of scalar + 1-D array + ASCII entries **plus the three adversarial IEEE float entries** (`0.1`, a denormal `5e-324`, and a 17-significant-digit value, from `change_list_factory`) is written then read back and is structurally equal: same `(parameter_name, array_index)` keys — **including the `Optional[int]` shape: scalar/string entries recover `array_index = None`, an N-element array recovers exactly the keys `(name, 0)…(name, N-1)`** — same values asserted with **exact equality (`==`), no float tolerance** — the float entries round-trip exactly only if the writer emits full `repr()`-precision binary64 text (LLR-004.8); a writer that dropped to `str()`/`%g`/fixed-width fails at least one adversarial float, so this assertion can genuinely fail — same categories, same order. The array entries exercise the **coalesce-on-write (LLR-004.9) → expand-on-read (LLR-005.6)** path: the N array-element entries collapse to one `VAL_BLK` `SW-INSTANCE` on write and re-expand to N entries on read; a writer that instead emitted one `SW-INSTANCE` per entry, or a reader that did not expand the `VG`, fails this assertion. See §5.5. |
| TC-025 | Patch Editor renders, edits and shows empty state | I | LLR-007.1, LLR-007.2, LLR-007.6 | HLR-007 | Under `App.run_test()`, an empty Patch Editor shows a neutral prompt; submitting name/index/value inputs adds a visible row and mutates the change-list; edit/remove update the rows; the `R-TUI-027` deferral notice is absent. |
| TC-026 | Patch Editor save and load actions | I | LLR-007.3, LLR-007.4 | HLR-007, HLR-004, HLR-005 | The save action writes a `.cdfx` to the work area and surfaces write issues via the status path; the load action populates visible change-list rows from a valid `.cdfx` and surfaces read issues. |
| TC-027a | Reader / Patch Editor rejects a billion-laughs `.cdfx` | U + I, analysis | LLR-006.6, LLR-007.4, LLR-005.2 | HLR-006, HLR-007, HLR-005 | Feeding `make_billion_laughs_cdfx` (a `DOCTYPE` with nested internal `<!ENTITY>` declarations, no `SYSTEM` reference) to the CDFX reader: the `DOCTYPE` is present, the reader surfaces **exactly one** `R-XML-PARSE` `ValidationIssue`, returns an **empty change-list**, and the parser **never expands an entity** (no nested-entity text in any parsed node, no expanded content in any issue message) — a deterministic verdict, not a timing one. The integration arm drives the same fixture through the Patch Editor load action: no uncaught exception, the screen stays usable. The `pytest` timeout is kept only as defense-in-depth (S-005). Backed by LLR-006.6 / DD-9; reviewed by the Phase 2 security-reviewer — see §5.5. |
| TC-027b | Reader rejects an external-entity (`SYSTEM`) `.cdfx` | U, analysis | LLR-006.6, LLR-005.2 | HLR-006, HLR-005 | Feeding `make_external_entity_cdfx` — a `DOCTYPE` with one external `<!ENTITY>` `SYSTEM` reference pointing at a test-created **sentinel temp file of known unique content** — to the CDFX reader: the reader surfaces **exactly one** `R-XML-PARSE` `ValidationIssue`, returns an empty change-list, no uncaught exception. The concrete no-external-read check: the sentinel content string is **absent** from every parsed value, entry field, and `ValidationIssue` message — proving the external file was never read and inlined. Backed by LLR-006.6 / DD-9; reviewed by the Phase 2 security-reviewer — see §5.5. |
| TC-028 | CDFX handler logic lives outside `app.py` | INSP | LLR-007.5 | HLR-007 | The §5.6 inspection checklist passes in full. |
| TC-029 | A2L name cross-check on load | U | LLR-008.1 | HLR-008 | With an A2L loaded, a `SW-INSTANCE` named for a non-existent A2L parameter yields exactly one `R-NAME-NOT-IN-A2L` warning. |
| TC-030 | A2L array-length cross-check on load | U | LLR-008.2 | HLR-008 | With an A2L loaded, a 4-element array `SW-INSTANCE` against a 3-element A2L parameter yields exactly one `R-ARRAY-LEN-MISMATCH` warning. |
| TC-031 | Cross-check skipped without an A2L | U | LLR-008.3 | HLR-008 | With no A2L loaded, a `.cdfx` parses into entries and emits zero `R-NAME-NOT-IN-A2L` / `R-ARRAY-LEN-MISMATCH` issues. |
| TC-032 | Writer emits a tool-identification note | U | LLR-004.7 | HLR-004 | A `.cdfx` written by the CDFX writer carries a leading `Created with s19_app CDF 2.0 Writer` XML comment, positioned so the document remains well-formed and re-parses via `ElementTree` without exception. |
| TC-033 | Writer emits round-trip-safe float values | U | LLR-004.8 | HLR-004 | Each of the three adversarial IEEE float physical values — `0.1`, the denormal `5e-324`, and a 17-significant-digit value, pinned in-memory as Python `float` (binary64) — is written then re-read by the CDFX reader; each recovered value compares **exactly equal (`==`)** to the original with no tolerance applied. The denormal would truncate to `0.0` and the 17-digit value would lose its tail under a `str()`/`%g`/fixed-width writer, so the test fails on any lossy representation and passes only under full `repr()`-precision `V` text. |
| TC-034 | Reader tolerates a writer / tool-identification note | U | LLR-006.7 | HLR-006 | A `.cdfx` from `make_tool_note_cdfx` carrying a leading `Created with …` XML comment reads every `SW-INSTANCE` and emits **zero** comment-related issues — the tool note is non-significant content, not a parse error or a `ValidationIssue`. |
| TC-035 | Read-path size and nesting-depth bound | U | LLR-006.8 | HLR-006 | Using `make_oversized_cdfx` and the fixture's **size-probe seam**: with the size-probe stubbed to report an over-256 MB byte size, the reader produces exactly one `R-XML-PARSE` issue, an empty change-list, and `ElementTree.parse` is never reached — the size check precedes parsing. A second arm feeds the deeply-nested variant: a document exceeding the element nesting-depth bound yields one `R-XML-PARSE` issue with no unbounded recursion. |
| TC-036 | CDFX write target is work-area-contained | I | LLR-007.7 | HLR-007 | Under `App.run_test()`, a Patch Editor save produces a `.cdfx` whose resolved path lies under `.s19tool/workarea/`; a write target that is, or whose traversed parents include, a symbolic link / NTFS reparse point is rejected with a write-side `ValidationIssue`, not a crash; a save onto an already-existing filename produces a dedup-suffixed file (`_<N>` before the suffix), never a silent clobber. |
| TC-037 | CDFX load path resolves the user-supplied path | U | LLR-005.5 | HLR-005 | A valid `.cdfx` path is resolved through `s19_app/tui/workspace.py` `resolve_input_path` and read; an unresolvable path yields exactly one `R-XML-PARSE` `ValidationIssue` and **no file is opened** (asserted via a no-open spy on the file-open seam). |
| TC-038 | Writer coalesces array-element entries; rejects sparse arrays | U | LLR-004.9, LLR-006.1 | HLR-004, HLR-006 | Three array-element entries `PARAM[0..2]` of one `parameter_name` produce **exactly one** `VAL_BLK` `SW-INSTANCE` with one `VG` of three `V` ordered ascending by `array_index`. A group with a gap (`PARAM[0]`, `PARAM[2]`, no `PARAM[1]`) and a group whose lowest index is not 0 (`PARAM[1]`, `PARAM[2]`) each produce **no** `SW-INSTANCE` for `PARAM` and **exactly one** `W-ARRAY-SPARSE` warning naming `PARAM`; the writer never synthesizes a `V` for a missing index. A change-list whose only entries are a sparse group yields a backbone-only `.cdfx` plus the `W-ARRAY-SPARSE` warning(s) and one `W-EMPTY-CHANGELIST` (LLR-004.6 zero-writable rule). |
| TC-039 | Reader expands a `VAL_BLK` instance into array-element entries | U | LLR-005.6 | HLR-005 | A `VAL_BLK` `SW-INSTANCE` whose `VG` holds N `V` elements expands to N change-list entries `(name, 0)…(name, N-1)`; a `VALUE`/`BOOLEAN` `SW-INSTANCE` expands to one scalar entry with `array_index is None`; an `ASCII` `SW-INSTANCE` expands to one string entry with `array_index is None`. |

**Reverse traceability check.** Every LLR-001.1 … LLR-008.3 (**44 LLRs** —
the 39-LLR set carried out of Phase 1 iteration 2, plus the three added in
iteration 3 (LLR-005.5, LLR-006.8, LLR-007.7) and the two added in the Phase-3
amendment (LLR-004.9, LLR-005.6)) appears in the "Covers LLR" column above;
the LLR-by-HLR-group tally is 4 + 4 + 3 + 9 + 6 + 8 + 7 + 3 = 44.
Every HLR-001 … HLR-008 (8 HLRs) maps to the TCs of its decomposed LLRs. All
eight `W-*` structural codes are exercised by the per-rule sub-cases
TC-019a … TC-019h; the two writer-behavior codes `W-INSTANCE-EXCLUDED` and
`W-ARRAY-SPARSE` are exercised by TC-019d and TC-038 respectively; all nine
core `R-*` codes are exercised by TC-016/TC-020/TC-021/TC-023, with the
`DOCTYPE`/entity-rejection case of `R-XML-PARSE` exercised by
TC-027a/TC-027b and the size/depth case by TC-035; the two cross-check `R-*`
codes are exercised by TC-029/TC-030. The catalogue holds **47 test cases** —
TC-001 … TC-018, the eight sub-cases TC-019a … TC-019h, TC-020 … TC-026, the
two sub-cases TC-027a/TC-027b, and TC-028 … TC-039.

### 5.8 Testability assessment and open-question status

**Weakly-testable requirements** (objectively verifiable, but with a stated
caveat):

- **HLR-004 / LLR-004.x — "structurally valid CDF 2.0".** Per constraint C-3
  and DD-2, validation is **structural only** — well-formedness plus the §7
  element/category/value rules — not XSD schema conformance. The test cases
  therefore verify *the documented rule set*, not *true ASAM-XSD validity*.
  "Valid `.cdfx`" in TC-011…TC-014 / TC-019a…TC-019h / TC-032 means "passes
  every `W-*` rule and matches the §3/§5 minimal-example shape", nothing
  stronger. This is recorded as OQ-1 / OQ-4 in §6.3, both now **RESOLVED** —
  structural-only is the confirmed batch oracle, with no XSD dependency.
- **LLR-006.1 — un-provokable writer-output invariants.** Four `W-*` codes
  (`W-XML-WELLFORMED`, `W-ROOT-MSRSW`, `W-BACKBONE`, `W-CATEGORY-VALUE-CONSISTENT`)
  are invariants a correct writer cannot violate — there is no fault path
  through the real writer that could provoke them. They are verified by feeding
  the **standalone `W-*` validator function** a deliberately-broken element
  tree (TC-019a/b/c/g), with the writer-cannot-provoke fact recorded by the
  `analysis` method on those sub-cases. This is a genuine testability caveat:
  the negative case exercises the validator in isolation, not the writer
  end-to-end. The five genuinely provokable codes (`W-INSTANCE-NAME`,
  `W-INSTANCE-CATEGORY`, `W-VALUE-PRESENT`, `W-EMPTY-CHANGELIST`, and the
  LLR-004.5 exclusion path) are exercised through the real writer.
- **HLR-004 — vCDM interoperability.** RK-2: no live vCDM and no sample
  `.cdfx` are available. No automated TC can assert real vCDM round-trip; the
  achievable acceptance criterion is "structurally valid per the rule set".
  Real vCDM interop stays a **manual, client-side check** and is out of the
  automated suite by design — not a testability gap to be closed this batch.
- **LLR-007.5 — module placement.** Verified by *inspection* (TC-028), not
  automated assertion. The checklist in §5.6 makes the verdict objective, but
  it remains a static review rather than a runtime test.
- **HLR-003 / HLR-007 — demo corroboration.** The `demo` method for these two
  is corroboration only; the pass/fail gate is the `test`-method TCs. The demo
  has no objective threshold and is not counted toward coverage.

All other HLRs/LLRs are objectively testable with the synthetic fixtures of
§5.4. No requirement was found *un*-testable.

**Open questions raised by this validation pass — OQ-4/OQ-5/OQ-6 RESOLVED,
OQ-7 OPEN but non-blocking:**

The three open questions this validation pass raised in iteration 1 (OQ-4,
OQ-5, OQ-6) have each been resolved by the architect in iteration 2; their
resolutions are recorded in §6.3. Iteration 3 raised one further, non-blocking
open question — **OQ-7** (the concrete CDF binary-notation lexeme) — which does
not gate Phase 3. All four are summarized here from the validation-strategy
perspective:

- **OQ-4 — definition of "valid" for the test oracle (extends OQ-1).
  RESOLVED.** Structural-only validation is confirmed for the batch: the test
  suite's notion of a valid `.cdfx` is exactly the `W-*` / `R-*` rule set of
  research §7 plus the §3/§5 shape, with no XSD dependency introduced. TC-011…
  TC-014 / TC-032 encode that rule set as the contract; the "structural-only"
  caveat above stays as a stated, accepted limitation rather than an open
  decision. True ASAM-XSD conformance is a deferred non-goal (C-2/C-3).
- **OQ-5 — XML entity-expansion defense.** RESOLVED. The architect added
  **LLR-006.6** (rewritten in iteration 3 as `DOCTYPE` / `<!ENTITY>` rejection
  on read) under HLR-006, so the security test cases TC-027a / TC-027b trace to
  a parent requirement — the qa-reviewer's iteration-1 recommendation was
  adopted. They are no longer orphan tests; they are the validation hook for
  LLR-006.6 and are still reviewed by the Phase 2 security-reviewer.
- **OQ-6 — float equality oracle for the round-trip (TC-024).** RESOLVED. The
  architect added **LLR-004.8** requiring the writer to emit IEEE float `V`
  values at full `repr()` precision. The round-trip oracle therefore asserts
  **exact float equality (`==`) with no tolerance**; TC-024's value comparison
  and the dedicated unit check TC-033 both rely on that guarantee. The
  in-memory value type is pinned as Python `float` (binary64) and TC-024 /
  TC-033 carry adversarial float fixtures (`0.1`, a denormal, a 17-digit value)
  so the round-trip test can genuinely fail under a lossy representation
  (closing finding Q-03). No tolerance / epsilon decision is pending.

- **OQ-7 — concrete CDF binary-notation lexeme for `V` text. OPEN
  (non-blocking; raised in Phase 1 iteration 3).** From the validation-strategy
  perspective: A-07 dropped `0b` as a normative CDF binary form, so TC-018
  asserts `0b101`→5 only as a **tolerant-superset** case, not as a normative
  requirement, and no TC fails if `0b` is not decoded. The binary lexeme is
  recorded as open in §6.3; it does not block Phase 3 and does not affect any
  coverage figure (`V` values in production `.cdfx` are overwhelmingly
  decimal / exponential). LLR-005.4 / TC-018 stay verifiable as written.

### 5.9 Batch acceptance criteria

The batch is accepted for Phase 4 sign-off when **all** of the following hold:

1. **Coverage** — 100% of the 8 HLRs and **44 LLRs** map to at least one TC
   with a recorded **pass** result (the §5.7 catalogue of **47 test cases** —
   TC-001 … TC-018, TC-019a … TC-019h, TC-020 … TC-026, TC-027a/TC-027b,
   TC-028 … TC-039 — is the coverage record).
2. **Method assigned** — no HLR or LLR is left without a validation method
   (§5.2 / §5.3 are complete).
3. **No blocker fails** — zero failing TCs at error/blocker severity. A
   warning-level finding may be accepted with a written justification.
4. **Rule-code completeness** — every `W-*` and `R-*` code of research §7 is
   provoked by a TC and emitted with the documented code and severity.
5. **Round-trip pass** — TC-024 passes: a scalar + 1-D array + ASCII
   change-list — including the three adversarial IEEE float entries — survives
   a write→read cycle structurally equal with exact float `==`.
6. **Security gate** — TC-027a and TC-027b both pass (each: a `DOCTYPE` /
   entity-bearing `.cdfx` surfaced as exactly one `R-XML-PARSE`
   `ValidationIssue`, an empty change-list, no entity ever expanded, no
   external file read, no uncaught exception) **and** the Phase 2
   security-reviewer has signed off on the `DOCTYPE`-rejection mitigation. The
   behavior is required by LLR-006.6 (OQ-5 resolved); TC-035 additionally
   confirms the LLR-006.8 size / nesting-depth bound; TC-036 confirms the
   LLR-007.7 write-path containment and TC-037 the LLR-005.5 load-path
   resolution.
7. **Collect-don't-abort honored** — every read-error TC (TC-016, TC-020,
   TC-023, TC-027a, TC-027b, TC-035, TC-037) confirms the reader returns issues
   without raising an uncaught exception.
8. **No new dependency** — TC-028's checklist confirms `pyproject.toml` /
   `requirements.txt` are unchanged (constraint C-2).
9. **Synthetic fixtures only** — every `.cdfx` / A2L / change-list fixture is
   synthetic (§5.4); no client artifact appears in `tests/` (constraint C-9).
10. **No regression** — the pre-batch `pytest` suite still passes; there is
    **no regression in the engine / parser / validation suites**. Note that
    LLR-006.3 adds `artifact = "cdfx"` to the `ValidationIssue` model, which
    may legitimately touch `validation/` and its tests — the gate is that those
    suites still pass, not that their files are byte-unmodified.
11. **Open questions resolved** — OQ-1…OQ-6 are all **RESOLVED**, each with a
    recorded decision in §6.3. **OQ-7** (the concrete CDF binary-notation
    lexeme) is **OPEN but explicitly non-blocking** — it does not gate Phase 3
    or Phase 4 sign-off (see §5.8 and §6.3); no test depends on its resolution.

---

## 6. Appendices

### 6.1 Extended glossary

See §1.3. Additional terms:

- **Resolution status** — per-entry state from HLR-002: one of `resolved`,
  `unresolved` (name not in A2L), `index-out-of-range`, `unresolved-no-a2l`.
- **Editable category set** — the `SW-INSTANCE` categories this batch can edit
  and write: `VALUE`, `BOOLEAN`, `VAL_BLK`, `ASCII`. Other categories are
  read-tolerated and read-only.
- **Backbone** — the mandatory CDFX container chain
  `MSRSW → SW-SYSTEMS → SW-SYSTEM → SW-INSTANCE-SPEC → SW-INSTANCE-TREE`.

### 6.2 Relevant design decisions

- **DD-1 — Target CDF 2.0.** Read and write target CDF 2.0 (`CDF20`). vCDM
  lists CDF 2.0 support; CDF 2.1-only features (structures, BLOBs, 3–5D
  cuboids) are outside the current A2L decode model. Reading tolerates other
  version tokens with an info issue. (design-input §2)
- **DD-2 — Structural validation, stdlib only.** CDFX validation is structural
  (well-formedness + element/category/value rules), implemented with
  `xml.etree.ElementTree`, no new runtime dependency. XSD validation is
  deferred (OQ-1). (constraints C-2, C-3)
- **DD-3 — Physical values stored, hex/ASCII display-only.** The change-list
  stores physical values (CDF-correct). The decimal/hex/ASCII rendering is a UI
  concern derived from the A2L data type and never changes the serialized
  value. (design-input §6, LLR-003.3)
- **DD-4 — Array element positions are positional `V` elements.** A 1-D array
  characteristic is written as a `VG` of positional `V` elements; element *k*
  is the *(k+1)*-th `V`. The change-list key `PARAMETER[0]` maps to the first
  `V`. The change-list field `array_index` is **not** serialized as the CDFX
  element `SW-ARRAY-INDEX` — `SW-ARRAY-INDEX` is an unrelated construct used
  only for `*_ARRAY` array-of-parameters categories (out of scope); `array_index`
  maps solely to positional `V` order inside the `VG` (A-09). (design-input §3,
  LLR-004.3)
- **DD-12 — Array-element entries coalesce to one `SW-INSTANCE`; sparse arrays
  are rejected, not gap-filled (Phase-3 amendment).** The change-list model
  keys entries by `(parameter_name, array_index)`, so a 1-D array is *N*
  separate entries. Standard ASAM CDF 2.0 (research §3/§5) represents an array
  as **one** `SW-INSTANCE` with one `VG` of positional `V` — not *N*
  same-`SHORT-NAME` instances, which vCDM would mis-read or reject. The writer
  therefore **coalesces** the *N* entries of one `parameter_name` into one
  `VAL_BLK` `SW-INSTANCE` (LLR-004.9) and the reader **expands** that instance
  back into *N* keyed entries (LLR-005.6); a write→read cycle is lossless
  (LLR-004.9 round-trip clause). To make coalescing decidable, `array_index`
  was changed to `Optional[int]` (LLR-001.1): `None` ≙ scalar/string, integer ≙
  array element. For a **sparse** array (a gap in the indices, or a lowest
  index ≠ 0) two options were weighed — **gap-fill** the missing slot, or
  **reject** the whole array group. Reject was chosen and made normative
  (`W-ARRAY-SPARSE`, LLR-004.9): gap-filling would write a physical value the
  engineer never entered into a `V` slot — silently shipping an unintended
  calibration value to the ECU — violating the verbatim-physical-value
  contract (DD-3 / LLR-003.3) and the fail-loud rule. Rejection is fully
  reversible: the engineer adds the missing index and re-saves. (Phase-3
  array-coalescing requirements gap; LLR-001.1, LLR-004.2, LLR-004.3,
  LLR-004.9, LLR-005.6)
- **DD-13 — `W-INSTANCE-EXCLUDED` / `W-ARRAY-SPARSE` are writer-behavior
  codes (Phase-3 amendment).** Increment 4 introduced `W-INSTANCE-EXCLUDED`
  ad-hoc for the LLR-004.5 per-entry exclusion warning; it is **formally
  adopted**, not renamed — it is descriptive and already tested, and research
  §7 already separates writer *behaviors* (tool-note, round-trip floats) from
  issue-emitting *rules*. `W-ARRAY-SPARSE` (LLR-004.9) is its sibling for the
  sparse-array rejection. Both are recorded in `design-input/cdfx-research.md`
  §7 under a "writer-behavior codes" heading so the `W-*` code set is complete
  and no code is undocumented drift. (LLR-004.5, LLR-004.9, LLR-006.1)
- **DD-5 — Reuse `ValidationIssue`.** All CDFX findings reuse the project's
  `ValidationIssue`/`ValidationSeverity` model with `artifact = "cdfx"`; no new
  issue model is introduced. (constraint C-5, LLR-006.3)
- **DD-6 — Handler in its own module.** CDFX read/write + change-list model
  live in a dedicated module; `app.py` holds only UI wiring. (constraint C-8,
  LLR-007.5)
- **DD-7 — Tool-identification note.** The writer emits a leading
  `Created with s19_app CDF 2.0 Writer` XML comment so produced files are
  self-describing; the reader tolerates and ignores any tool note (CANape or
  otherwise). Grounded in the owner's observation that production `.cdfx`
  files are CANape-produced and carry such a note. (design-input §2.1,
  LLR-004.7, LLR-006.7)
- **DD-8 — Round-trip-safe float serialization.** The writer emits IEEE float
  `V` values at full `repr()` precision, making write→read exact and removing
  the need for a float tolerance in the round-trip oracle. (OQ-6, LLR-004.8)
- **DD-9 — XML entity safety via `DOCTYPE` rejection, stdlib-only.** The reader
  **rejects** any `.cdfx` carrying a `DOCTYPE` or `<!ENTITY>` declaration — a
  conformant CDF 2.0 `.cdfx` needs none — using an
  `xml.etree.ElementTree.XMLParser` whose DTD / entity-declaration handler
  raises; a malicious `.cdfx` is surfaced as one `R-XML-PARSE` issue. The
  earlier "disabled or safely bounded" wording is **dropped**: stdlib
  `ElementTree` has no expansion-count bound and still expands internal
  entities, so "safely bounded" was not a mitigation the stdlib actually
  provides (S-004). **C-2-vs-security tradeoff (explicit decision):** **no
  `defusedxml`** — or any other — runtime dependency is added;
  `DOCTYPE`-rejection is the stdlib-only answer that neutralizes both the
  billion-laughs and external-entity vectors and keeps constraint C-2 intact.
  (OQ-5, LLR-006.6; size / depth bound is the separate DD-11.)
- **DD-10 — `.cdfx` saved into the work area under `workspace.py` guards.**
  The product owner decided that a saved `.cdfx` is written **into
  `.s19tool/workarea/`** and protected by the existing `workspace.py`
  containment guards — work-area resolution, reparse-point (symlink / junction)
  rejection, and existing-file dedup-suffix / confirm — reusing
  `copy_into_workarea` / `_path_traverses_reparse_point` rather than a new
  write path. This is the lowest-risk, lowest-new-code resolution: the work
  area is already the home of every other on-disk artifact and an "open work
  area" action already exists, so the produced `.cdfx` is still reachable. The
  rejected alternative — free-path "Save As" export — would have required the
  *same* traversal / symlink / overwrite guards anyway; it only moves the
  obligation, it does not remove it. The load path resolves the user-supplied
  path through `resolve_input_path`; reading a `.cdfx` from outside the work
  area is permitted, but the path is still resolved through the shared helper.
  (S-001, S-002; A-6, OQ-3; LLR-005.5, LLR-007.7)
- **DD-11 — Read-path size and nesting-depth cap.** The reader rejects any
  `.cdfx` over a 256 MB byte cap (`DEFAULT_COPY_SIZE_CAP_BYTES`, reusing the
  `workspace.py` ingest-cap rationale) checked **before** parsing, and bounds
  XML nesting depth; both are surfaced as `R-XML-PARSE` collect-don't-abort
  issues. This caps the plain-but-huge and deeply-nested resource-exhaustion
  vectors that the entity defense (DD-9) does not cover. (S-003, LLR-006.8)

### 6.3 Open risks and open questions

**Open questions — OQ-1…OQ-6 RESOLVED (Phase 1 iterations 2–3; decisions
recorded below); OQ-7 OPEN but non-blocking (raised in iteration 3):**

- **OQ-1 — XSD schema validation dependency. RESOLVED:** structural-only
  validation with stdlib `xml.etree.ElementTree`, no new runtime dependency;
  true ASAM-XSD conformance is a deferred non-goal (constraints C-2/C-3,
  DD-2).
- **OQ-2 — `SW-INSTANCE-TREE` `CATEGORY` value. RESOLVED:** the
  `SW-INSTANCE-TREE` `CATEGORY` is `NO_VCD` (no variant coding); variant-coded
  datasets are out of scope.
- **OQ-3 — Work-area placement of `.cdfx` files. RESOLVED (revised, Phase 1
  iteration 3):** a saved `.cdfx` is written **into `.s19tool/workarea/`** and
  protected by the existing `workspace.py` containment guards (work-area
  resolution, reparse-point rejection, existing-file dedup/confirm). It is
  **not** a `.s19tool/` *project* artifact and is **not** subject to
  `validate_project_files` — but the containment guarantee that scoping removed
  from `validate_project_files` is **replaced** by LLR-007.7 (write path) and
  LLR-005.5 (load path), **not** dropped. The earlier iteration-2 wording
  ("free-standing export, not subject to containment") is **superseded**: a
  `.cdfx` is a work-area-contained exchange artifact, not a free-path export
  (assumption A-6; security finding S-001). The product-owner decision is
  recorded as DD-10.
- **OQ-4 — definition of "valid" for the test oracle. RESOLVED:** the test
  oracle is exactly the `W-*` / `R-*` structural rule set of research §7 plus
  the §3/§5 minimal-example shape; XSD conformance is out of scope (same
  decision as OQ-1; constraint C-3).
- **OQ-5 — XML entity-expansion defense has no LLR. RESOLVED:** LLR-006.6 now
  mandates entity-expansion / external-entity safety on read, giving security
  test case TC-027 a traceable parent requirement.
- **OQ-6 — float equality oracle for the round-trip. RESOLVED:** LLR-004.8
  requires the writer to emit round-trip-safe full-precision (`repr()`)
  float values, so TC-024 can assert exact float equality with no tolerance.
- **OQ-7 — concrete CDF binary-notation lexeme for `V` text. OPEN (raised
  Phase 1 iteration 3):** Research §3 establishes that CDF allows `V` text in
  binary notation but does not pin the exact prefix. The `0b` prefix used in
  earlier drafts is the **Python** integer-literal form and is not confirmed by
  the research as the CDF lexeme. LLR-005.4 now states "binary notation in the
  form defined by CDF" and no test asserts `0b` as the normative form
  (A-07). **Resolution path:** confirm the binary lexeme against the CDF
  specification or a real `.cdfx` sample; until then the reader may accept
  `0b` as a tolerant superset. *Severity: low — `V` values in production
  `.cdfx` are overwhelmingly decimal/exponential; binary `V` text is an edge
  case. This OQ does not block Phase 3.*

**Open risks:**

- **RK-1 — No client `.cdfx` sample.** All CDFX structure is from public
  documentation. Producer-specific variation (namespaces, `ADMIN-DATA`, history
  blocks) is mitigated by tolerant reading (LLR-005.3) but cannot be fully
  verified without a real sample. *Severity: medium.*
- **RK-2 — vCDM interop unverified.** vCDM compatibility is asserted from
  documentation, not tested against a live vCDM. The achievable acceptance
  criterion is "structurally valid CDF 2.0 per the rule set"; real vCDM
  round-trip is a client-side manual check. *Severity: medium.*
- **RK-3 — XML namespace handling.** If real `.cdfx` files declare an `xmlns`,
  `ElementTree` tag matching becomes namespace-qualified. LLR-005.3 (revised in
  iteration 3) now carries an explicit `shall` clause requiring local-name
  matching regardless of namespace, and scopes the `SW-INSTANCE` search to the
  `SW-INSTANCE-TREE` backbone (closing finding A-06 / S-006). The residual risk
  is reduced to verifying the behavior against a real namespaced sample, which
  is itself bounded by RK-1. *Severity: low.*
- **RK-4 — Scope creep toward applying changes.** Applying the change-list to
  firmware, exporting modified S19/HEX, and undo/redo are explicitly out of
  scope; any LLR drifting there must be rejected at phase-2 review. *Severity:
  low (governance).*
- **RK-5 — Physical vs. raw value confusion.** If the engineer expects to enter
  raw bytes, the physical-value model (DD-3) could surprise them. Mitigated by
  type-driven display (HLR-003) making the value form explicit. *Severity:
  low.*
