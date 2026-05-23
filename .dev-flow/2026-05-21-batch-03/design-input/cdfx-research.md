# CDFX Format Research Summary — s19_app batch-03

> **Status:** design-input, source-of-truth for `01-requirements.md`.
> **Author:** architect agent. **Date:** 2026-05-21.
> **Purpose:** establish what ASAM CDF / `.cdfx` is, which parts matter for a
> parameter change-list, the version to target, and the read/write validation
> rules — without a client `.cdfx` sample, derived from public sources.

---

## 1. What CDF / CDFX is

**ASAM MCD-2 CDF** ("Calibration Data Format") is an ASAM standard for storing
**ECU calibration parameter values plus development-process metadata**
(maturity level, history, author, comments). `.cdfx` is its **XML
serialization** (UTF-8; the `.xml` extension is also legal). ASAM ships both an
**XSD** and a **DTD** for formal validation.

CDF is **complementary to ASAM MCD-2 MC (the A2L format)**: A2L *describes* the
parameters (address, data type, record layout, conversion / `COMPU_METHOD`,
limits); CDF *carries the values* for those parameters. A CDF instance is
matched to its A2L definition **by name** (`SHORT-NAME`). CDF stores
**physical values**, not raw implementation bytes — the spec requires the
stored physical value to carry enough precision to reconstruct the raw value
via the A2L `COMPU_METHOD`. CDF supports all MCD-2 MC data elements except
`CUBOID`.

This is directly relevant to s19_app: the app already resolves A2L
characteristics to address + data type + decode metadata (`tui/a2l.py`). A CDFX
change-list is therefore a **set of named physical values keyed to A2L
characteristic names** — a natural companion artifact to the A2L the app
already loads.

## 2. Version landscape and version decision

| Version | Year | Notes |
|---------|------|-------|
| CDF 1.0 | 2002 | XML-based but poorly adopted; abandoned. **Ignore.** |
| **CDF 2.0** | 2006 | Complete redesign on the MSRSW DTD 3.0 base. Category token `CDF20`. "Very stable and successful"; the de-facto industry baseline. |
| CDF 2.1 | — | Adds MCD-2 MC 1.7 compatibility: structured types, BLOBs, 3–5D look-up tables (`CUBOID`, `CUBE_4`, `CUBE_5`), model links. Category token `CDF21`. |

**Decision — target CDF 2.0 (`CATEGORY` = `CDF20`) for read AND write.**

Rationale:
- vCDM / vCDMcenter explicitly lists **"CDF 2.0"** among supported formats
  (Vector product information). Targeting 2.0 maximizes vCDM round-trip
  compatibility, which is the batch's stated goal.
- The s19_app A2L parser handles **scalar and 1-D array** characteristics
  (`DATATYPE_SIZES`, `element_count`, `_decode_raw_value` array path). It does
  **not** model structures, unions, BLOBs or 3–5D cuboids. The CDF 2.1-only
  features are out of reach of the current A2L model anyway.
- CDF 2.0 is the simpler, better-understood schema — consistent with the
  project's "collect issues, don't abort" culture and the
  "no new runtime dependency" constraint.

**Read tolerance:** the reader **shall accept** a file whose `MSRSW/CATEGORY`
is `CDF20` *or* `CDF21` (a 2.1 producer may still emit only 2.0-compatible
instances), but **shall emit an informational issue** when the category is not
`CDF20`, and **shall emit a warning** for any instance whose `CATEGORY` is a
2.1-only type (`STRUCTURE`, `UNION`, `*_ARRAY`, `CUBOID`, `CUBE_4`, `CUBE_5`).
Unknown/2.1 instances are skipped, not fatal. **Write** always emits `CDF20`.

### 2.1 Reference writer — Vector CANape (owner-supplied observation)

> **Owner-supplied observation (2026-05-21).** The project owner inspected
> several real production `.cdfx` files. All were produced by **Vector CANape**
> and carried a tool-identification note reading *"Created with CANape … CDF
> 2.0 Writer"* — most likely a leading XML comment, though it could equally be
> a tool field in `ADMIN-DATA` / `SW-CS` metadata; the exact placement was not
> confirmed.

Implications for s19_app:

- **Vector CANape is the de-facto reference CDF 2.0 writer** in the ecosystem
  s19_app's `.cdfx` files must coexist with. CANape is also the dominant
  upstream of files the reader will be asked to load.
- The observed note **confirms the CDF 2.0 target** of §2 — production tooling
  is emitting CDF 2.0, not 2.1, for the parameter-change-list use case.
- A tool-identification note is therefore an **expected, conventional** part of
  a real `.cdfx`. s19_app **should** (a) emit its own writer note so the files
  it produces are self-describing and consistent with the CANape-dominated
  ecosystem, and (b) tolerate and ignore any tool note — from CANape or any
  other producer — on read, treating it as non-significant content rather than
  a parse error. These two behaviors are carried into `01-requirements.md` as
  LLR-004.7 (write) and LLR-006.7 (read).

## 3. XML structure — the nine levels

The `.cdfx` document is a nested XML tree. The element names below are the
**public schema contract** (verbatim from the ASAM CDF wiki):

```
MSRSW                              (1) root; has SHORT-NAME + CATEGORY
└── SW-SYSTEMS
    └── SW-SYSTEM                  (2) one SW-SYSTEM per ECU / dataset
        └── SW-INSTANCE-SPEC       (3) formal aggregation layer
            └── SW-INSTANCE-TREE   (4) one calibration dataset
                ├── SW-INSTANCE-TREE-ORIGIN   (5) variant / origin metadata
                └── SW-INSTANCE    (6) ONE PARAMETER  ← the unit of a change-list
                    ├── SHORT-NAME                  parameter name (A2L key)
                    ├── CATEGORY                    VALUE | VAL_BLK | CURVE | ...
                    ├── SW-ARRAY-INDEX              (only inside an array element)
                    ├── SW-FEATURE-REF              owning function/feature (optional)
                    ├── SW-VALUE-CONT               (7) value container
                    │   ├── SW-VALUES-PHYS          (8) mandatory; holds the values
                    │   │   ├── V                   (9) one numeric value
                    │   │   ├── VT                  (9) one text/string value
                    │   │   └── VG                      value group (arrays/axes)
                    │   └── SW-VALUE-CONT child meta
                    ├── SW-AXIS-CONT                value container for an axis
                    ├── SW-CS-HISTORY               quality / change history metadata
                    └── SW-CS-FLAGS                 process metadata (maturity, etc.)
```

Key facts:
- **`MSRSW/SHORT-NAME` + `MSRSW/CATEGORY`** — the root identity. `CATEGORY`
  carries the version token (`CDF20`).
- **`SW-INSTANCE`** is the per-parameter record. **Its `SHORT-NAME` is the
  identity used to match the parameter against the loaded A2L**
  (`CHARACTERISTIC` / `MEASUREMENT` name).
- **`CATEGORY`** on an instance declares the parameter shape. The 14 defined
  types: `VALUE`, `DEPENDENT_VALUE`, `BOOLEAN`, `ASCII`, `VAL_BLK`, `CURVE`,
  `MAP`, `COM_AXIS`, `CURVE_AXIS`, `RES_AXIS`, `STRUCTURE`, `UNION`,
  `VALUE_ARRAY`, `CURVE_ARRAY`, `MAP_ARRAY`, `STRUCTURE_ARRAY`.
- **`SW-VALUE-CONT` → `SW-VALUES-PHYS`** holds the actual values for a
  parameter; **`SW-AXIS-CONT` → `SW-VALUES-PHYS`** does the same for an axis.
  `SW-VALUES-PHYS` is **mandatory** inside a value container.
- **`V`** = one **numeric** value. The spec allows the *text content* of `V`
  in decimal, exponential, hexadecimal, or binary notation. **Caveat:** public
  sources confirm that binary notation is *permitted* but do not pin the exact
  binary-prefix lexeme. The `0b` prefix is the **Python** integer-literal form
  and is **not** confirmed here as the CDF lexeme — `01-requirements.md`
  LLR-005.4 therefore says "binary notation in the form defined by CDF" and the
  concrete lexeme is carried as open question OQ-7 (non-blocking).
- **`VT`** = one **text / string** value (used for `ASCII` parameters, enum
  labels).
- **`VG`** = a **value group** — an optional aggregation that nests `V`/`VT`
  (or further `VG`) to give arrays and tables their row/column shape.
- **`SW-ARRAY-INDEX`** — present on a `SW-INSTANCE` only when that instance is
  itself an element of an array-of-parameters (`*_ARRAY` categories). It is
  **not** how a single array characteristic's element positions are
  represented — those are positional `V` elements inside `SW-VALUES-PHYS`
  (optionally grouped by `VG`).

### How array element positions are represented (decision for `PARAMETER[0]`)

For a single array-valued characteristic (`VAL_BLK` / `CURVE`, the kind
s19_app's A2L `element_count > 1` produces), the element values are a
**positional sequence of `V` elements** inside `SW-VALUES-PHYS`. CDF/XML has
**no explicit per-element index attribute** for the simple array case — order
is significant; element *k* is the *(k+1)-th* `V`.

Therefore the s19_app change-list entry `PARAMETER[0] : 23` maps to:
"the 1st `<V>` of the `SW-VALUES-PHYS` of the `SW-INSTANCE` whose `SHORT-NAME`
is `PARAMETER`, holding physical value 23." A scalar (`VALUE`) parameter has
exactly one `V`.

> **Change-list-model note (Phase-3 amendment).** The `01-requirements.md`
> change-list model keys entries by `(parameter_name, array_index)`, so a 1-D
> array characteristic is stored as *N* separate `ChangeListEntry` rows
> (`PARAMETER[0]`, `PARAMETER[1]`, …). Because standard CDF represents that
> array as **one** `SW-INSTANCE` with one `VG` of *N* positional `V` — never
> *N* repeated same-`SHORT-NAME` instances — the writer **coalesces** the *N*
> entries into one `VAL_BLK` `SW-INSTANCE` and the reader **expands** that
> instance back into *N* entries (`01-requirements.md` LLR-004.9 / LLR-005.6).
> A **scalar** or **string** parameter is one entry whose `array_index` is
> `None` (LLR-001.1) and maps to one `SW-INSTANCE` with a bare `V` / `VT`; an
> **array** parameter's entries carry an integer `array_index`. A sparse array
> (a gap, or a non-zero lowest index) has no positional CDF encoding and is
> rejected on write with a `W-ARRAY-SPARSE` warning rather than gap-filled
> (LLR-004.9).

**Scope boundary:** 2-D `MAP` parameters, shared axes, and arrays-of-parameters
(`*_ARRAY`) are **read-tolerated** (parsed and surfaced as issues / read-only
rows) but the change-list **edit/write path targets scalars and 1-D arrays
only** this batch — matching the A2L decode model the app already has. Multi-
dimensional editing is a deferral, not a requirement.

## 4. Elements relevant to a parameter change-list

For a write that vCDM can consume, the **minimum viable** `SW-INSTANCE` needs:

| Element | Role in the change-list | Required? |
|---------|-------------------------|-----------|
| `MSRSW` + `SHORT-NAME` + `CATEGORY=CDF20` | document identity / version | yes |
| `SW-SYSTEMS/SW-SYSTEM/SHORT-NAME` | dataset/ECU container | yes |
| `SW-INSTANCE-SPEC/SW-INSTANCE-TREE/SHORT-NAME` | the calibration set | yes |
| `SW-INSTANCE/SHORT-NAME` | **A2L name — the join key** | yes |
| `SW-INSTANCE/CATEGORY` | `VALUE` (scalar) or `VAL_BLK` (1-D array) | yes |
| `SW-VALUE-CONT/SW-VALUES-PHYS/V` | the changed numeric value(s) | yes |
| `SW-VALUE-CONT/SW-VALUES-PHYS/VT` | string value for `ASCII` parameters | conditional |
| `SW-VALUE-CONT/UNIT-DISPLAY-NAME` | physical unit text (cosmetic) | optional |
| `SW-INSTANCE/SW-CS-FLAGS`, `SW-CS-HISTORY` | maturity / who-changed-it | optional, out of scope |

The s19_app change-list does **not** need `SW-FEATURE-REF`, variant coding,
quality history, or axis containers for the scalar+1-D-array scope. Writing the
mandatory backbone + `SW-INSTANCE` per changed parameter is sufficient and
schema-valid.

## 5. Annotated minimal example

A complete, schema-shaped CDF 2.0 file carrying a change-list of one scalar and
one 1-D array parameter. This is the **target write output shape**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<MSRSW>
  <SHORT-NAME>S19APP_PATCH</SHORT-NAME>          <!-- document identity -->
  <CATEGORY>CDF20</CATEGORY>                      <!-- version token: CDF 2.0 -->
  <SW-SYSTEMS>
    <SW-SYSTEM>
      <SHORT-NAME>ECU1</SHORT-NAME>               <!-- one ECU / dataset -->
      <SW-INSTANCE-SPEC>
        <SW-INSTANCE-TREE>
          <SHORT-NAME>PatchSet</SHORT-NAME>       <!-- the calibration dataset -->
          <CATEGORY>NO_VCD</CATEGORY>             <!-- non-variant-coded dataset -->

          <!-- ===== change-list entry 1: a scalar parameter ===== -->
          <SW-INSTANCE>
            <SHORT-NAME>IGN_ADVANCE_BASE</SHORT-NAME>  <!-- matches A2L CHARACTERISTIC name -->
            <CATEGORY>VALUE</CATEGORY>                  <!-- scalar -->
            <SW-VALUE-CONT>
              <SW-VALUES-PHYS>
                <V>12.5</V>                             <!-- one numeric physical value -->
              </SW-VALUES-PHYS>
            </SW-VALUE-CONT>
          </SW-INSTANCE>

          <!-- ===== change-list entry 2: a 1-D array parameter ===== -->
          <SW-INSTANCE>
            <SHORT-NAME>FUEL_TRIM_TABLE</SHORT-NAME>    <!-- A2L array characteristic -->
            <CATEGORY>VAL_BLK</CATEGORY>                <!-- array, up to 3-D; here 1-D -->
            <SW-VALUE-CONT>
              <SW-VALUES-PHYS>
                <VG>                                    <!-- value group = the array -->
                  <V>23</V>                             <!-- element [0] -->
                  <V>24</V>                             <!-- element [1] -->
                  <V>25</V>                             <!-- element [2] -->
                </VG>
              </SW-VALUES-PHYS>
            </SW-VALUE-CONT>
          </SW-INSTANCE>

          <!-- ===== change-list entry 3: an ASCII (string) parameter ===== -->
          <SW-INSTANCE>
            <SHORT-NAME>CAL_LABEL</SHORT-NAME>
            <CATEGORY>ASCII</CATEGORY>
            <SW-VALUE-CONT>
              <SW-VALUES-PHYS>
                <VT>REV_C</VT>                          <!-- text value -->
              </SW-VALUES-PHYS>
            </SW-VALUE-CONT>
          </SW-INSTANCE>

        </SW-INSTANCE-TREE>
      </SW-INSTANCE-SPEC>
    </SW-SYSTEM>
  </SW-SYSTEMS>
</MSRSW>
```

> Notes on producer variation: real-world `.cdfx` files from MCD tools may add
> an `xmlns`, an `<ADMIN-DATA>` block, `<SW-CS-COLLECTIONS>`, or wrap instances
> with `<SW-CS-HISTORY>`. The reader must be **tolerant** — locate elements by
> tag name regardless of surrounding optional siblings, ignore unrecognized
> elements, and never abort on an unknown-but-well-formed element. The writer
> emits the **minimal valid subset** above.

## 6. Value display format proposal (decimal / hex / ASCII / string)

The s19_app change-list shows each value "in the best form." Because CDF stores
**physical** values while the A2L data type describes the **implementation**
type, the display form is driven by the **A2L data type of the resolved
parameter** (from `tui/a2l.py` `decode_type` / `datatype`):

| A2L data type (from `DATATYPE_SIZES`) | CDF instance `CATEGORY` | Change-list display form |
|---------------------------------------|-------------------------|--------------------------|
| `UBYTE` `UWORD` `ULONG` `A_UINT64` (unsigned int) | `VALUE` / `VAL_BLK` | **decimal**, with **hex** shown alongside (`23` / `0x17`) |
| `SBYTE` `SWORD` `SLONG` `A_INT64` (signed int) | `VALUE` / `VAL_BLK` | **decimal** (signed) |
| `FLOAT16/32/64_IEEE` | `VALUE` / `VAL_BLK` | **decimal** with fractional digits (e.g. `12.5`) |
| single `UBYTE` array forming text (A2L `ASCII` / string char.) | `ASCII` | **ASCII string** in quotes |
| boolean-like (0/1 via `COMPU_VTAB`) | `BOOLEAN` / `VALUE` | **decimal** plus the enum label if a `COMPU_VTAB` resolves |

Rule of thumb encoded as a requirement: the display form **shall** be derived
from the A2L data type of the resolved parameter — unsigned integers show
decimal + hex, signed integers show signed decimal, floats show fractional
decimal, ASCII/string characteristics show a quoted string. The `.cdfx` file
itself always carries the **physical** value as `V` (numeric, decimal or
exponential) or `VT` (text); the hex/ASCII rendering is a **UI concern only**
and does not change what is serialized.

## 7. CDFX read/write validation rules (source-of-truth for requirements)

Mirror the project's `ValidationIssue` collect-don't-abort pattern. Each rule
below becomes an issue **code** with a severity. Errors mean "not usable";
warnings/info mean "usable but flagged."

> **Validation is structural-only, stdlib-only.** Per `01-requirements.md`
> constraints C-2/C-3 (resolution of OQ-1/OQ-4) a `.cdfx` is "valid" exactly
> when it passes the `W-*` / `R-*` rules below, checked with the stdlib
> `xml.etree.ElementTree`. True ASAM-XSD schema conformance is a deferred
> non-goal — no `lxml`/`xmlschema` dependency and no licensed ASAM XSD are
> introduced this batch.

### On WRITE (produce a `.cdfx`)

**Structural rules** — the eight `W-*` codes that flag a *malformed writer
output*:
- **W-XML-WELLFORMED** (error): output must be well-formed UTF-8 XML.
- **W-ROOT-MSRSW** (error): root element is `MSRSW` with a non-empty
  `SHORT-NAME` and `CATEGORY=CDF20`.
- **W-BACKBONE** (error): `SW-SYSTEMS/SW-SYSTEM/SW-INSTANCE-SPEC/SW-INSTANCE-TREE`
  chain present with `SHORT-NAME`s.
- **W-INSTANCE-NAME** (error): every `SW-INSTANCE` has a non-empty `SHORT-NAME`.
- **W-INSTANCE-CATEGORY** (error): every `SW-INSTANCE` `CATEGORY` is one of the
  supported set (`VALUE`, `VAL_BLK`, `ASCII`, `BOOLEAN`).
- **W-VALUE-PRESENT** (error): every `SW-INSTANCE` has a `SW-VALUE-CONT/`
  `SW-VALUES-PHYS` with at least one `V` (or `VT` for `ASCII`).
- **W-CATEGORY-VALUE-CONSISTENT** (error): a `VALUE`/`BOOLEAN` instance has
  exactly one `V`; a `VAL_BLK` instance has a `VG` (or ≥1 `V`); an `ASCII`
  instance has exactly one `VT`.
- **W-EMPTY-CHANGELIST** (warning): writing a change-list with zero writable
  entries.

**Writer-behavior codes** — `W-*` codes that flag a *writer decision to drop
input that cannot be represented in standard CDF*, not a malformed output.
Distinct from the eight structural rules above; both kinds are
`ValidationIssue`s with stable codes (`01-requirements.md` LLR-006.1, DD-13):
- **W-INSTANCE-EXCLUDED** (warning): an unresolved or index-out-of-range
  change-list entry was excluded from the output — one per excluded entry
  (`01-requirements.md` LLR-004.5).
- **W-ARRAY-SPARSE** (warning): a 1-D array `parameter_name` whose
  change-list entries' `array_index` values do **not** form the contiguous
  zero-based sequence `0…N-1` (a gap, or a lowest index ≠ 0) was excluded
  whole — standard CDF has no positional encoding for a sparse array and the
  writer does not synthesize a value for a missing index — one per rejected
  array group (`01-requirements.md` LLR-004.9).

Two further write behaviors are required by `01-requirements.md` LLR-004.7 and
LLR-004.8 but are **not** issue-emitting codes at all — they are writer-output
properties verified directly by their test cases:
- **Tool-identification note** — the writer emits a leading
  `Created with s19_app CDF 2.0 Writer` XML comment (LLR-004.7); the note must
  not break `W-XML-WELLFORMED`.
- **Round-trip-safe floats** — IEEE float `V` text is emitted at full
  `repr()` precision so a write→read cycle is exact (LLR-004.8).

### On READ (parse + validate a `.cdfx`)
- **R-XML-PARSE** (error): the file parses as well-formed XML; a parse failure
  is one issue, not a crash. This code **also** covers a maliciously
  constructed `.cdfx` and resource-exhaustion vectors:
  - A `DOCTYPE` or `<!ENTITY>` declaration — the vehicle for both the
    nested-entity ("billion-laughs") amplification and the external-entity
    (`SYSTEM`/`PUBLIC`) file-read vector — is **rejected outright**. A
    conformant CDF 2.0 `.cdfx` needs no `DOCTYPE`, so the reader parses with an
    `xml.etree.ElementTree.XMLParser` whose DTD / entity-declaration handler
    raises on the first such declaration. Stdlib `ElementTree` has no
    expansion-count bound and still expands internal entities, so "disabled or
    safely bounded" is **not** a mitigation the stdlib provides —
    `DOCTYPE`-rejection is the concrete stdlib-only defense and no `defusedxml`
    dependency is introduced (`01-requirements.md` LLR-006.6, DD-9).
  - A plain, well-formed but oversized (> 256 MB) `.cdfx`, or one whose XML
    nesting depth exceeds a documented bound, is likewise surfaced as one
    `R-XML-PARSE` issue — the size check runs **before** parsing
    (`01-requirements.md` LLR-006.8, DD-11).
  In every case the condition is surfaced as one `R-XML-PARSE` issue, without
  memory exhaustion, hang, external file read, or uncaught exception (security
  test case TC-027).
- **R-ROOT-MSRSW** (error): root is `MSRSW`.
- **R-VERSION-UNKNOWN** (info): `MSRSW/CATEGORY` is not `CDF20` (e.g. `CDF21`,
  missing) — file still read, version noted.
- **R-BACKBONE-MISSING** (error): the `SW-INSTANCE-TREE` backbone cannot be
  located — no instances can be read.
- **R-INSTANCE-NO-NAME** (error): a `SW-INSTANCE` lacks a `SHORT-NAME`; that
  instance is skipped, others continue.
- **R-INSTANCE-NO-VALUE** (error): a `SW-INSTANCE` has no readable
  `SW-VALUES-PHYS` value; instance skipped.
- **R-CATEGORY-UNSUPPORTED** (warning): instance `CATEGORY` is a 2.1-only or
  multi-dimensional type (`MAP`, `STRUCTURE`, `*_ARRAY`, `CUBOID`, …); the
  instance is surfaced read-only and excluded from the editable change-list.
- **R-CATEGORY-VALUE-MISMATCH** (warning): value count does not match the
  category (e.g. `VALUE` with 3 `V`s) — value(s) still read, mismatch flagged.
- **R-VALUE-NOT-NUMERIC** (warning): a `V` text content does not parse as a
  number in decimal/exponential/hex/binary — value kept as raw text, flagged.
- **R-NAME-NOT-IN-A2L** (warning, cross-check): a `SW-INSTANCE` `SHORT-NAME`
  does not match any loaded A2L `CHARACTERISTIC`/`MEASUREMENT` — entry loaded
  but unresolved (analogous to the existing `symbol-only-in-MAC` warning).
- **R-ARRAY-LEN-MISMATCH** (warning, cross-check): the number of array elements
  read differs from the A2L `element_count` for that parameter.

**Not a violation on read.** A writer- or tool-identification note — including
a leading `Created with CANape … CDF 2.0 Writer` (or s19_app) XML comment, see
§2.1 — is **non-significant content**: the reader tolerates and ignores it and
emits **no** issue for it (`01-requirements.md` LLR-006.7). XML comments and
unrecognized-but-well-formed optional elements never trigger an `R-*` code.

These codes are the contract `01-requirements.md` LLRs trace to and that the
qa-reviewer pass will turn into test cases.

## 8. Open questions for the requirements / design phase

> **Status (2026-05-21, Phase 1 iteration 2): all resolved.** The resolutions
> below are recorded in `01-requirements.md` §6.3 (OQ-1…OQ-6).

1. **XSD schema validation vs. structural validation. RESOLVED.** Python's
   stdlib `xml.etree.ElementTree` parses XML and catches well-formedness errors
   but **cannot validate against an XSD**. Full schema conformance would need
   `lxml` or `xmlschema` (a new runtime dependency) plus the licensed,
   non-redistributable ASAM CDF XSD. **Decision:** validation is
   **structural-only, stdlib-only** — the §7 `W-*`/`R-*` rule set with
   `xml.etree.ElementTree`, no new dependency. True ASAM-XSD conformance is a
   deferred non-goal (requirements C-2/C-3, OQ-1/OQ-4).
2. **vCDM round-trip not testable here.** No vCDM license or sample `.cdfx` is
   available; vCDM compatibility is asserted from documentation (vCDM supports
   "CDF 2.0"), not verified. The acceptance criterion can only be "schema-shaped
   per §3/§5 + structurally valid per §7" — true vCDM interop is a manual,
   client-side check and is called out as residual risk RK-2. *(Residual risk,
   not an open question — no decision pending.)*
3. **Physical vs. raw values. RESOLVED.** CDF mandates *physical* values;
   s19_app's A2L layer can produce both. **Decision:** the change-list stores
   and writes the **physical** value (CDF-correct); raw/hex is display-only
   (§6, requirements DD-3 / LLR-003.3).
4. **`SW-INSTANCE-TREE` `CATEGORY`. RESOLVED.** The `SW-INSTANCE-TREE`
   `CATEGORY` is **`NO_VCD`** (no variant coding); variant-coded datasets are
   out of scope (requirements OQ-2).
5. **Work-area placement of `.cdfx`. RESOLVED (revised, Phase 1 iteration 3).**
   A saved `.cdfx` is a **work-area-contained artifact** — written into
   `.s19tool/workarea/` and protected by the existing `workspace.py`
   containment guards (`copy_into_workarea` / `_path_traverses_reparse_point`):
   work-area resolution, reparse-point rejection, existing-file dedup/confirm.
   It is **not** a `.s19tool/` *project* artifact (not subject to
   `validate_project_files`), but the containment guarantee is **replaced**,
   not dropped. The load path resolves the user-supplied path through
   `resolve_input_path`. The earlier "free-standing export, not subject to
   containment" wording is **superseded** (requirements OQ-3 / A-6 / DD-10,
   LLR-005.5 / LLR-007.7; security finding S-001 / S-002).
6. **XML entity-expansion / external-entity safety. RESOLVED (revised, Phase 1
   iteration 3).** The reader **rejects** any `.cdfx` carrying a `DOCTYPE` or
   `<!ENTITY>` declaration via an `XMLParser` whose DTD / entity-declaration
   handler raises — a conformant CDF 2.0 `.cdfx` needs none. This is the
   concrete stdlib-only mitigation; the earlier "disabled or safely bounded"
   wording is dropped because stdlib `ElementTree` provides no such bound and
   still expands internal entities. No `defusedxml` dependency is introduced
   (the C-2-vs-security decision). A separate 256 MB byte cap plus a
   nesting-depth bound covers the plain-but-huge / deeply-nested vectors. A
   malicious `.cdfx` is surfaced as an `R-XML-PARSE` issue. Carried as
   requirements LLR-006.6 + LLR-006.8 (OQ-5; DD-9 / DD-11), the traceable
   parents of security test case TC-027.
7. **Round-trip-safe float serialization. RESOLVED.** The writer emits IEEE
   float `V` values at full `repr()` precision so a write→read cycle is exact,
   removing any float-tolerance need in the round-trip oracle (requirements
   LLR-004.8 / OQ-6).

## 9. Citations

- ASAM CDF — Wiki (version history, nine levels, MSRSW, SW-INSTANCE, CATEGORY
  types, V/VT/VG, arrays/axes, MCD-2 MC relationship):
  https://www.asam.net/standards/detail/cdf/wiki/
- ASAM CDF — standard detail page:
  https://www.asam.net/standards/detail/cdf/
- ASAM MCD-2 MC (A2L) — Wiki:
  https://www.asam.net/standards/detail/mcd-2-mc/wiki/
- IANA media type registration `application/CDFX+XML`:
  https://www.iana.org/assignments/media-types/application/CDFX+XML
- MathWorks — Get Started with / Working With ASAM CDFX Files in MATLAB
  (instance/value model, `getValue`/`setValue`, multidimensional + axes):
  https://www.mathworks.com/help/vnt/ug/working-with-asam-cdfx-files-in-matlab.html
- MathWorks — CDFX files overview:
  https://www.mathworks.com/help/vnt/cdfx-files.html
- MathWorks — `coder.cdf.export` (CDF per ASAM AE CDF, XSD/DTD schema option):
  https://www.mathworks.com/help/rtw/ref/coder.cdf.export.html
- Vector — vCDM / vCDMcenter Product Information (CDF 2.0 among supported
  formats; XML-based CDF carries maturity/history/author/comments metadata):
  https://cdn.vector.com/cms/content/products/vcdm/Docs/vCDM_ProductInformation_EN.pdf
- Vector — vCDMstudio product page:
  https://www.vector.com/int/en/products/products-a-z/software/vcdm/vcdmstudio/

> All structural detail is from public documentation. No client `.cdfx` sample
> was available; producer-specific variation (namespaces, ADMIN-DATA, history
> blocks) is handled by tolerant reading (§5 note).
