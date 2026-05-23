# Functionality — s19_app — 2026-05-21-batch-03 (functional Patch Editor + ASAM CDFX)

**Audience:** a technical stakeholder, future engineer, or QA reviewer who needs to understand what batch-03 added to `s19_app` — the parameter change-list, A2L resolution, type-driven value display, the functional Patch Editor screen, and the ASAM CDFX (`.cdfx`) read/write handler — and what was deliberately left unbuilt.

**Purpose:** describe (a) what the batch is and why it adds a data-processing layer, (b) the change-list model, (c) A2L parameter resolution, (d) type-driven value display, (e) the functional Patch Editor screen, (f) the CDFX writer, (g) the CDFX reader and its validation rule set, (h) the XML-safety guarantees, and (i) what is explicitly deferred.

**Scope:** this is the **orientation document**. It is *not* the requirements specification ([`01-requirements.md`](../01-requirements.md)), *not* the per-test verdict register ([`04-validation.md`](../04-validation.md)), and *not* the traceability matrix ([`traceability-matrix.md`](traceability-matrix.md)). It lets a new reader navigate those artefacts. For the visual call-graph see [`diagrams/architecture.md`](diagrams/architecture.md).

---

## 1. What batch-03 is

`s19_app` (distribution name `s19tool`) is an offline desktop tool for parsing, validating and visualising automotive memory artefacts — S-record / Intel HEX firmware images, ASAM A2L description files, and MAC `TAG=hexaddr` symbol files. It ships two entry points: `s19tool` (Rich CLI) and `s19tui` (Textual TUI).

Batch `2026-05-20-batch-02` delivered the `s19tui` TUI's **Patch Editor** rail screen (item 6) as an **inert view shell** — a before/after hex-pane layout with input fields wired to nothing, plus a visible deferral notice (`R-TUI-027`). Batch `2026-05-21-batch-03` **replaces that shell with a working tool** that lets a calibration engineer:

1. **Build a parameter change-list** — a structured set of intended calibration-value changes, each keyed to an A2L parameter name and array index (e.g. `PARAMETER[0] : 23`).
2. **Resolve each entry** against the loaded A2L to learn the parameter's data type and validity.
3. **See each value** in the form best suited to its A2L data type.
4. **Save the change-list as a `.cdfx` file** — a structurally valid ASAM CDF 2.0 calibration-data exchange artefact, for hand-off to Vector vCDM.
5. **Load a `.cdfx` file** back into the Patch Editor, validating it and surfacing every problem as an issue rather than crashing.

Unlike batch-02 (a view-layer-only restyle on a frozen engine), this batch **deliberately adds a data-processing layer** — that expansion was approved and expected ([`01-requirements.md`](../01-requirements.md) §1.1). The new layer is the `s19_app/tui/cdfx/` package (change-list model + CDFX read/write handler) plus a `s19_app/tui/services/cdfx_service.py` orchestration seam.

The **engine remains frozen.** The Phase-4 `git diff main` over `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` is empty — zero bytes changed ([`04-validation.md`](../04-validation.md) §2). The CDFX feature is purely additive new files; it **reuses** the A2L parser (`tui/a2l.py`), the `ValidationIssue` / `ValidationSeverity` model (`validation/model.py`), the severity-to-colour policy (`tui/color_policy.py`) and the workspace helpers (`tui/workspace.py`) without re-implementing any of them.

### 1.1 What the batch delivered

| Output | Count | Where |
|--------|-------|-------|
| User stories | 7 (US-001..US-007) | [`01-requirements.md`](../01-requirements.md) §2.6 |
| High-level requirements | 8 (HLR-001..HLR-008) | [`01-requirements.md`](../01-requirements.md) §3 |
| Low-level requirements | 44 | [`01-requirements.md`](../01-requirements.md) §4 |
| Test cases | 47 (TC-001..TC-018, TC-019a..h, TC-020..TC-026, TC-027a/b, TC-028..TC-039) | [`01-requirements.md`](../01-requirements.md) §5.7; verdicts in [`04-validation.md`](../04-validation.md) §5 |
| Phase 3 increments | 11 | [`03-increments/increment-001.md`](../03-increments/increment-001.md) … [`increment-011.md`](../03-increments/increment-011.md) |
| New `s19_app/tui/cdfx/` modules | 6 (`__init__.py`, `changelist.py`, `resolve.py`, `display.py`, `writer.py`, `reader.py`) | see §10 |
| New service module | 1 (`s19_app/tui/services/cdfx_service.py`) | see §6 |
| New `R-*` rows in the living `REQUIREMENTS.md` | 18 (`R-CDFX-001`..`R-CDFX-018`) | repo-root [`REQUIREMENTS.md`](../../../REQUIREMENTS.md) |
| Phase 4 verdict | `pass-with-gaps` (0 blockers) | [`04-validation.md`](../04-validation.md) §9 |

---

## 2. The parameter change-list

The change-list is the central artefact of the Patch Editor (HLR-001). It is a structured model — pure data, no XML, no Textual import — implemented in `s19_app/tui/cdfx/changelist.py`.

- **Entry structure (LLR-001.1).** Each entry (`ChangeListEntry`) holds at least: `parameter_name` (str), `array_index` (`Optional[int]`), `value` (the entered physical value — `int | float | str | None`), and a resolution-status field. The `array_index` is **`None`** for a scalar parameter (`VALUE` / `BOOLEAN`) and for an ASCII-string parameter, and a **non-negative integer *k*** for element *k* of a 1-D array parameter (`VAL_BLK`).
- **Why `Optional[int]`.** This was a Phase-3 amendment. An earlier `int`-with-default-`0` model made a scalar entry and element 0 of a single-element array indistinguishable — both `(name, 0)` — so the writer could not decide between a scalar `VALUE` instance and a `VAL_BLK` instance. Making `array_index` `Optional[int]` gives the writer and reader an unambiguous scalar-vs-array discriminator.
- **Entry identity (LLR-001.3).** The pair `(parameter_name, array_index)` is the entry identity. `(name, None)` and `(name, 0)` are **distinct** identities — a scalar entry and element 0 of an array under the same name are different rows. An add that targets an existing identity **updates** that entry in place rather than creating a duplicate.
- **Operations (LLR-001.2).** The model provides add, edit (the value of an entry identified by name + index) and remove (an entry by name + index).
- **Deterministic ordering (LLR-001.4).** The model exposes its entries in a deterministic order so repeated serialization of the same change-list produces byte-identical `SW-INSTANCE` ordering.

---

## 3. A2L parameter resolution

Each change-list entry names an A2L parameter but carries no type metadata of its own. Resolution (HLR-002, `s19_app/tui/cdfx/resolve.py`) looks an entry up against the **loaded A2L** so the writer and the display layer know the parameter's data type, element count and characteristic kind.

- **Reuses the A2L parser, never re-parses (constraint C-1).** Resolution runs through the **enriched** A2L pipeline — `parse_a2l_file` → `extract_a2l_tags` → `enrich_a2l_tags_with_values` — *not* bare `extract_a2l_tags`. A bare `extract_a2l_tags` tag for a `CHARACTERISTIC` has `datatype = None`; the decode-relevant fields (`decode_type`, `element_count`, `char_type`) are populated only after enrichment. `resolve.py` consumes that enriched output and never modifies `a2l.py`.
- **Four resolution states.** Each entry's resolution status is one of:
  - `resolved` — the name (and index, if any) matched a loaded A2L parameter; the entry carries the resolved type metadata.
  - `unresolved` — the `parameter_name` matches no A2L parameter (LLR-002.2).
  - `index-out-of-range` — the integer `array_index` is negative or not less than the A2L `element_count` (LLR-002.3). An entry whose `array_index` is `None` (scalar/string) is **not** range-checked.
  - `unresolved-no-a2l` — no A2L is loaded; every entry is marked this way (LLR-002.4).
- **Never raises.** Resolution is collect-don't-abort: an unknown name, an out-of-range index, or a missing A2L produces a status flag, never an exception. The change-list stays usable.

---

## 4. Type-driven value display

A value is **stored** as its physical value (CDF-correct) and **displayed** in the form best suited to the resolved A2L data type (HLR-003, `s19_app/tui/cdfx/display.py`). Display is a UI concern derived from the A2L type — it never changes the stored value (LLR-003.3).

The display form is selected from the pair `(char_type, datatype)` of the resolved parameter (LLR-003.1):

| Resolved parameter | Display form |
|--------------------|--------------|
| `ASCII` `char_type` (string parameter) | a quoted string |
| Unsigned integer (`UBYTE`, `UWORD`, `ULONG`, `A_UINT64`) | decimal, with a hexadecimal companion **only when the physical value is integral** |
| Signed integer (`SBYTE`, `SWORD`, `SLONG`, `A_INT64`) | signed decimal |
| IEEE float (`FLOAT16_IEEE`, `FLOAT32_IEEE`, `FLOAT64_IEEE`) | fractional decimal |
| Unresolved entry (no A2L type available) | plain decimal text, no exception (LLR-003.2) |

**The integral-hex condition.** The hexadecimal companion is shown for an unsigned-integer parameter only when the stored physical value is an exact integer. A non-IDENTICAL `COMPU_METHOD` can yield a fractional physical value, and `hex()` of a fractional value has no meaning — so for such a parameter the display renders decimal only, with no hexadecimal companion. `ASCII` is an A2L `char_type` attribute (orthogonal to the numeric `datatype` — there is no `ASCII` `datatype` token), so the quoted-string form is selected from `char_type`, not `datatype`.

---

## 5. The functional Patch Editor screen

The Patch Editor rail screen (item 6, `PatchEditorPanel` in `s19_app/tui/screens_directionb.py`) is made **functional** (HLR-007), superseding the inert view shell delivered under `R-TUI-027`.

- **Renders the change-list (LLR-007.1).** The static placeholder hex panes of the inert shell are replaced by a row per change-list entry showing the parameter name, array index (blank for a `None`-index scalar/string entry), displayed value and resolution status.
- **Add / edit / remove wired (LLR-007.2).** The parameter-name, index and value inputs are wired to the change-list model's add, edit and remove operations. The index input maps an empty string to a `None`-index scalar entry and a typed integer to an array element.
- **Save action (LLR-007.3).** Triggering the save action invokes the CDFX writer to produce a `.cdfx` file inside `.s19tool/workarea/` through the work-area-contained write path; write `ValidationIssue` results surface via the existing status path.
- **Load action (LLR-007.4).** Triggering the load action with a `.cdfx` path invokes the CDFX reader through the path-resolving load path, populates the change-list from the parsed entries, and surfaces read issues.
- **Empty state (LLR-007.6).** With an empty change-list the screen shows a single neutral empty-state line prompting the engineer to add an entry or load a `.cdfx` — not a blank pane, a placeholder error, or a stack trace.
- **Module placement (LLR-007.5, constraint C-8).** All CDFX read/write and change-list logic lives in the dedicated `cdfx` package and the `cdfx_service.py` service seam. `app.py` holds **only** UI-state wiring — the Patch Editor action handler routes through `self._cdfx_service`; there is no `xml.etree.ElementTree` import and no XML parse/serialize call in `app.py` (verified by inspection, TC-028).

The service seam — `CdfxService` in `s19_app/tui/services/cdfx_service.py` — owns a single `ChangeList` and exposes `add_entry` / `edit_entry` / `remove_entry`, `rows` (resolve + render display rows), `save` and `load`. It mirrors the existing `a2l_service.enrich_tags_and_render` pattern so the screen and `app.py` stay presentational and carry no XML / model logic.

---

## 6. CDFX write — producing a `.cdfx`

The CDFX writer (`s19_app/tui/cdfx/writer.py`, `write_cdfx` / `write_cdfx_to_workarea`) serializes a resolved change-list into a structurally valid **CDF 2.0** `.cdfx` document, using the Python standard library `xml.etree.ElementTree` only — no new runtime dependency (constraint C-2).

- **The CDF 2.0 backbone (LLR-004.1).** The writer emits an `MSRSW` root with a non-empty `SHORT-NAME` and a `CATEGORY` of `CDF20`, plus the container chain `SW-SYSTEMS → SW-SYSTEM → SW-INSTANCE-SPEC → SW-INSTANCE-TREE`, each container carrying a `SHORT-NAME`.
- **One `SW-INSTANCE` per resolved parameter (LLR-004.2).** The writer emits exactly **one `SW-INSTANCE` per distinct resolved `parameter_name`** — not one per change-list entry. Each instance carries a `SHORT-NAME` equal to the parameter name, a `CATEGORY` from the editable set (`VALUE` / `BOOLEAN` for scalars, `VAL_BLK` for 1-D arrays, `ASCII` for strings), and a `SW-VALUE-CONT/SW-VALUES-PHYS` element.
- **Value encoding (LLR-004.3).** A scalar entry is encoded as a single bare `V` directly inside `SW-VALUES-PHYS`; an ASCII string entry as a single `VT`; a 1-D array as a single `VG` containing one positional `V` per element, ordered ascending by `array_index`. The `array_index` is serialized **only** as the positional order of the `V` elements inside the `VG` — never as a `SW-ARRAY-INDEX` element (`SW-ARRAY-INDEX` is an unrelated CDFX construct for array-of-parameters categories, out of scope).
- **Array coalescing (LLR-004.9 — Phase-3 amendment).** Because the change-list keys entries by `(parameter_name, array_index)`, a 3-element array is **three** entries. Standard ASAM CDF 2.0 represents an array as **one** `SW-INSTANCE`. Before emitting, the writer **coalesces** all integer-`array_index` entries that share a `parameter_name` into a single `VAL_BLK` `SW-INSTANCE` with one `VG` of ascending positional `V`. `None`-index entries are not coalesced — each is its own scalar/string instance.
- **Sparse-array rejection (LLR-004.9).** If the integer indices of a coalesced group do **not** form the contiguous, gapless, zero-based sequence `0, 1, …, N-1` — a gap, or a lowest index ≠ 0 — the writer treats the whole array as a write-side error: it **excludes the entire `parameter_name` group** and emits exactly one warning-level issue `W-ARRAY-SPARSE`. The writer **never gap-fills, defaults, interpolates, or synthesizes** a value for a missing index. The rationale is calibration safety: gap-filling would write a physical value the engineer never entered into a `V` slot, silently shipping an unintended ECU value via vCDM. Rejection is fully reversible — the engineer adds the missing index and re-saves.
- **Unresolved entries excluded (LLR-004.5).** Unresolved or index-out-of-range entries are excluded from the output, each producing one warning-level issue `W-INSTANCE-EXCLUDED`.
- **Empty-change-list reporting (LLR-004.6).** If a write has zero *writable* entries — literally empty, or every entry excluded — the writer still emits a valid backbone-only `.cdfx` plus exactly one warning `W-EMPTY-CHANGELIST` (in addition to any per-entry exclusion warnings).
- **Tool-identification note (LLR-004.7).** The writer emits a leading XML comment `Created with s19_app CDF 2.0 Writer`, placed so the output remains well-formed — production `.cdfx` files in the Vector-CANape ecosystem carry such a note.
- **Well-formed UTF-8 XML (LLR-004.4).** The output is well-formed XML, UTF-8 encoded, with an XML declaration, re-parseable by `ElementTree`.
- **Round-trip-safe floats (LLR-004.8).** An IEEE float physical value is emitted in a full-precision textual representation equivalent to Python `repr()` of the float, so a write→read cycle is exact and needs no float tolerance.

`W-INSTANCE-EXCLUDED` and `W-ARRAY-SPARSE` are **writer-behavior codes** — they flag a writer *decision to drop input that cannot be represented*, distinct from the eight `W-*` structural *rule* codes that flag a malformed output. Both kinds are `ValidationIssue`s with stable codes; the distinction is documentation only (`design-input/cdfx-research.md` §7).

---

## 7. CDFX read — parsing and validating a `.cdfx`

The CDFX reader (`s19_app/tui/cdfx/reader.py`, `read_cdfx`) parses a `.cdfx` document back into a change-list and collects every read-time finding as a `ValidationIssue` **without aborting the load** (HLR-005 / HLR-006), mirroring the project's collect-don't-abort culture — a malformed instance is skipped and flagged, never thrown.

- **Well-formed parse into entries (LLR-005.1).** The reader parses with `ElementTree`, locates each `SW-INSTANCE` under the instance-tree backbone, and produces change-list entries.
- **`VAL_BLK` expansion (LLR-005.6 — Phase-3 amendment).** The read-side inverse of the writer's coalescing: a `VAL_BLK` instance whose `VG` holds *N* `V` elements is **expanded** into *N* entries `(name, 0)…(name, N-1)`; a `VALUE`/`BOOLEAN` instance → one scalar entry (`array_index is None`); an `ASCII` instance → one string entry (`array_index is None`). Coalesce-on-write then expand-on-read reproduces the `(parameter_name, array_index)` key set exactly — a write→read cycle is lossless.
- **Producer-variation tolerance (LLR-005.3).** The reader matches `MSRSW` / `SW-INSTANCE` / `V` by element **local name regardless of XML namespace** — a default `xmlns` makes `ElementTree` return tags as `{uri}LocalName`, so the reader strips the `{...}` prefix before matching. It scopes the `SW-INSTANCE` search **only to descendants of the `SW-INSTANCE-TREE` backbone** (so a crafted instance placed inside, e.g., `ADMIN-DATA` is not absorbed), and ignores unrecognized optional siblings (`ADMIN-DATA`, `SW-CS-HISTORY`, `SW-CS-FLAGS`).
- **Numeric notation decode (LLR-005.4).** A `V` element's text is decoded from decimal, exponential or hexadecimal (`0x`-prefixed) notation. Binary notation is handled in the form defined by CDF; `0b` is accepted as a tolerant superset only — the concrete CDF binary lexeme is an open question (OQ-7), and no test asserts `0b` as normative.
- **Tool-note tolerance (LLR-006.7).** A leading or embedded writer/tool-identification XML comment (e.g. `Created with CANape … CDF 2.0 Writer`) is treated as non-significant content — not a parse error, not a `ValidationIssue`.
- **Load-path resolution (LLR-005.5).** A user-supplied `.cdfx` path is resolved through `workspace.resolve_input_path` before opening — reusing the shared helper, not re-implementing path resolution. Reading a `.cdfx` from outside the work area is permitted (it is an exchange artefact that may legitimately arrive from elsewhere), but the path is still resolved through the shared helper. A path that cannot be resolved is surfaced as one `R-XML-PARSE` issue, with no file opened.

### 7.1 The validation rule set

The reader applies the read-time `R-*` structural rules of `design-input/cdfx-research.md` §7 (HLR-006, LLR-006.2), emitting one `ValidationIssue` per violation with the rule's documented code and severity:

| Code | Meaning | Severity |
|------|---------|----------|
| `R-XML-PARSE` | not well-formed XML / `DOCTYPE` present / over the size cap / depth-bound exceeded | error |
| `R-ROOT-MSRSW` | root element is not `MSRSW` | error |
| `R-VERSION-UNKNOWN` | `MSRSW/CATEGORY` is not `CDF20` (the reader tolerates it and continues — LLR-006.4) | info |
| `R-BACKBONE-MISSING` | the `SW-SYSTEMS…SW-INSTANCE-TREE` backbone is absent | error |
| `R-INSTANCE-NO-NAME` | a `SW-INSTANCE` has no `SHORT-NAME` | error |
| `R-INSTANCE-NO-VALUE` | a `SW-INSTANCE` has no value element | error |
| `R-CATEGORY-UNSUPPORTED` | a `CATEGORY` outside the editable set, e.g. `MAP` / `STRUCTURE` — the entry loads **read-only**, not fatal (LLR-006.5) | warning |
| `R-CATEGORY-VALUE-MISMATCH` | the value shape disagrees with the declared `CATEGORY` | error |
| `R-VALUE-NOT-NUMERIC` | a `V` element's text is not a decodable number | error |

Two further `R-*` codes are the A2L cross-check (§8). Every CDFX finding — write-side and read-side — is a `ValidationIssue` (`s19_app/validation/model.py`) with `artifact` set to `cdfx`, and its severity round-trips through `color_policy.css_class_for_severity` to a valid `sev-*` CSS class (LLR-006.3). The `ValidationIssue` model is reused **as-is** — `artifact="cdfx"` is passed as a string argument; no model edit was needed.

---

## 8. A2L cross-check on load

When a `.cdfx` is loaded **while an A2L is loaded**, the reader cross-checks each parsed `SW-INSTANCE` against the A2L (HLR-008), surfacing stale or mismatched change-lists analogous to the existing A2L↔MAC cross-checks:

- `R-NAME-NOT-IN-A2L` (warning, LLR-008.1) — a `SW-INSTANCE` whose name matches no A2L parameter.
- `R-ARRAY-LEN-MISMATCH` (warning, LLR-008.2) — an array `SW-INSTANCE` whose `V` count differs from the A2L `element_count` of the matched parameter.

While **no A2L is loaded**, the reader emits neither cross-check issue and still parses the `.cdfx` into entries (LLR-008.3).

---

## 9. XML-safety guarantees

A `.cdfx` received from outside is **untrusted input**. The reader is hardened against the well-known XML attack vectors using the standard library only — no `defusedxml` or any other new dependency (constraint C-2, design decision DD-9):

- **`DOCTYPE` / `<!ENTITY>` rejection (LLR-006.6).** A conformant CDF 2.0 `.cdfx` needs no `DOCTYPE` and no `<!ENTITY>` declaration. The reader parses with an `xml.etree.ElementTree.XMLParser` whose `expat`-level DTD / entity-declaration handler **raises on the first such declaration** — *before* any entity can be declared or expanded. This is the concrete, deterministic, stdlib-only defence: it neutralizes both the **billion-laughs** (internal-entity amplification) and the **external-entity** (`SYSTEM`/`PUBLIC` file-read) vectors with one rule. Stdlib `ElementTree` has no expansion-count bound and still expands internal entities, so rejecting the declaration is the only stdlib-correct answer. A malicious `.cdfx` is surfaced as exactly one `R-XML-PARSE` issue with an empty change-list — no entity expanded, no external file read, no memory exhaustion, no hang, no uncaught exception.
- **Read-path size cap (LLR-006.8).** Before parsing, the reader rejects any `.cdfx` whose on-disk byte size exceeds **256 MB** (`DEFAULT_COPY_SIZE_CAP_BYTES`, reusing the `workspace.py` ingest-cap rationale). The size check runs **before** `ElementTree.parse`, so an oversized file is never loaded into memory at all — this caps the plain-but-huge resource-exhaustion vector the entity defence does not address.
- **Nesting-depth bound (LLR-006.8).** The reader bounds XML element nesting depth, surfacing a document that exceeds the bound as one `R-XML-PARSE` issue rather than by unbounded recursion or memory growth.
- **Write-path containment (LLR-007.7).** The CDFX write path resolves and containment-validates its target the same way `workspace.copy_into_workarea` does — reusing `copy_into_workarea` / `_path_traverses_reparse_point`, not a re-implementation. The resolved target lies under a `.s19tool/workarea/` root; a target that is, or whose traversed parents include, a symbolic link or NTFS reparse point is rejected; a target whose name already exists is dedup-suffixed (`_<N>` before the suffix), never silently clobbered. Any containment / reparse-point / overwrite rejection is surfaced as a write-side `ValidationIssue`, not an uncaught exception.

All four are verified by dedicated test cases (TC-027a/b, TC-035, TC-036, TC-037) and the Phase-2 security-reviewer signed off on the `DOCTYPE`-rejection mitigation ([`04-validation.md`](../04-validation.md) §7 #6).

---

## 10. What is deferred

The batch was scoped strictly — build the change-list, read/write the calibration file, make the screen functional. The following are **explicitly out of scope** ([`01-requirements.md`](../01-requirements.md) §1.2) and are the subject of follow-up batches:

- **Apply-to-image.** Applying the change-list to the firmware image / memory map. The CDFX handler never modifies, parses against, or writes the firmware S19/HEX image — the change-list and the `.cdfx` are independent artefacts (constraint C-7). The CLI's `patch-hex` command is unaffected.
- **Modified-image export.** Exporting a modified S19 / Intel HEX file.
- **Undo / redo.** No history of edits.
- **XSD schema validation.** Validation this batch is **structural-only** — a `.cdfx` is "valid" exactly when it passes the documented `W-*` / `R-*` structural rule set of `design-input/cdfx-research.md` §7 (well-formedness + element/category/value rules). True ASAM-XSD conformance is a deferred non-goal: it would require a new dependency (`lxml`/`xmlschema`) plus the licensed, non-redistributable ASAM CDF XSD (constraint C-3, OQ-1/OQ-4 resolved).
- **Memory values.** The change-list stores and writes **physical** values (CDF-correct); there is no raw-byte entry path. Raw/hex rendering is a display concern only.
- **Multi-dimensional parameters.** 2-D maps (`MAP`), shared axes, structured/union types and arrays-of-parameters (`*_ARRAY`) are **read-tolerated** (parsed, surfaced as an `R-CATEGORY-UNSUPPORTED` issue, shown read-only) but **not editable / not writable** this batch.
- **vCDM round-trip verification.** No live vCDM installation or sample `.cdfx` is available — vCDM compatibility is asserted from Vector documentation, not verified against a live instance. This is an accepted residual risk (RK-2).

---

## 11. New modules and how to verify

| Module | Role | Built in |
|--------|------|----------|
| `s19_app/tui/cdfx/__init__.py` | Narrow public import surface — re-exports `ChangeList` / `ChangeListEntry` / `ResolutionStatus` / `read_cdfx` / `write_cdfx` / `write_cdfx_to_workarea` / `validate_w_rules` | increments 1, 7 |
| `s19_app/tui/cdfx/changelist.py` | The pure change-list model — `ChangeListEntry` / `ChangeList` / `ResolutionStatus`, `array_index` is `Optional[int]` | increment 1 (migrated in 5) |
| `s19_app/tui/cdfx/resolve.py` | A2L parameter resolution against the enriched A2L payload | increment 2 (migrated in 5) |
| `s19_app/tui/cdfx/display.py` | Type-driven value display formatting | increment 3 |
| `s19_app/tui/cdfx/writer.py` | CDFX writer + array coalescing + the standalone `W-*` validator | increments 4, 6, 8 |
| `s19_app/tui/cdfx/reader.py` | CDFX reader + `VAL_BLK` expansion + `R-*` validation + XML-safety + A2L cross-check | increments 7, 8 |
| `s19_app/tui/services/cdfx_service.py` | `CdfxService` — the orchestration seam between the Patch Editor / `app.py` and the `cdfx` package | increment 9 |

The CDFX package lives under `s19_app/tui/` as a peer of `tui/a2l.py` / `tui/mac.py` (the project's established home for format handlers), consistent with the `parsers → engine → tui` architecture and the `CLAUDE.md` rule that new feature logic extends a service rather than `app.py`.

**To run the suite and read verdicts:**

```bash
pytest -q                              # full suite — 611 passed / 0 failed / 3 xfailed / 2 skipped
pytest tests/test_cdfx_changelist.py   # change-list model
pytest tests/test_cdfx_resolve.py      # A2L parameter resolution
pytest tests/test_cdfx_display.py      # type-driven value display
pytest tests/test_cdfx_writer.py       # CDFX writer
pytest tests/test_cdfx_w_rules.py      # W-* write-time rule set
pytest tests/test_cdfx_reader.py       # CDFX reader
pytest tests/test_cdfx_r_rules.py      # R-* read-time rule set + A2L cross-check
pytest tests/test_cdfx_roundtrip.py    # write→read round-trip (TC-024)
pytest tests/test_cdfx_safety.py       # XML-safety — DOCTYPE / entity / size / depth
pytest tests/test_cdfx_path_containment.py   # load/write path resolution
pytest tests/test_tui_patch_editor.py        # the functional Patch Editor screen
pytest tests/test_tui_patch_containment.py   # work-area write containment via the screen
```

The CDFX + Patch Editor subset is 12 test files, **192 passed / 0 failed**. The pre-existing 2 skips and 3 xfails are inherited batch-01/batch-02 baseline cases — they are **not** CDFX cases.

**To launch the TUI with the Patch Editor:**

```bash
s19tui --load examples/case_00_public/prg.s19
```

Open the Patch Editor (rail item 6), add/edit/remove change-list entries, then save and load a `.cdfx`.

---

## 12. Where to go next

- The full requirement → test trace: [`traceability-matrix.md`](traceability-matrix.md).
- The per-test and per-requirement verdicts: [`04-validation.md`](../04-validation.md).
- The visual architecture and data-flow diagrams: [`diagrams/architecture.md`](diagrams/architecture.md).
- The CDFX format research and the `W-*`/`R-*` rule set: [`design-input/cdfx-research.md`](../design-input/cdfx-research.md).
- The four `-with-gaps` items (no client `.cdfx` sample, vCDM interop, `ruff` in CI, manual Patch Editor pass): [`04-validation.md`](../04-validation.md) §8 and [`traceability-matrix.md`](traceability-matrix.md) §3.
- The living requirements with the 18 new `R-CDFX-*` rows: repo-root [`REQUIREMENTS.md`](../../../REQUIREMENTS.md).
