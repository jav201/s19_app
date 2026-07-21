# Requirements Document — s19_app — Batch 58 (CRC Algorithm Designer "Variant B" view + engine prerequisites)

> Artifact language: **English** (engineering batch). Normative keyword: `shall`.
> Governing design (APPROVED, adopted verbatim): `docs/crc-algorithm-designer/01-requirements.md`
> (§6 engine E4/E5/E6, §7 view R-CRC-DSN-001..011, §8 AT table, §5 presets, §3.2 coverage oracles).
> Batch-57 headless keel (MERGED #110, `84180b4`) is REUSED, not rebuilt.
> Branch: `feat/batch-58-crc-designer-view` (base `84180b4` = origin/main).

---

## 1. Introduction

### 1.1 Purpose
Specify the batch-58 increment: the **CRC Algorithm Designer TUI view** (Variant B — an authoring-and-preview bench that never writes firmware) plus the three remaining **headless engine prerequisites** (E4 word codec, E5 template-loader facade, E6 job up-converter + `emit_job`) that the batch-57 keel did not yet ship. Engine-first, mirroring the Flow-Builder "keel first" order.

### 1.2 Scope
**In scope**
- Engine (headless, `s19_app/tui/operations/`, non-frozen):
  - E4 — big-endian / wider-field word codec `encode_word`/`decode_word`, with `encode_le`/`decode_le` kept byte-identical.
  - E5 — a `crc_template.py` loader **facade** re-exporting the already-shipped collect-don't-abort template loader.
  - E6 — extend `parse_job` to up-convert today's flat `crc_config` (regions/groups) into the internal target list, and add an `emit_job` serializer.
- View (`#screen_crc_designer`, a new rail screen on the rail-8/`.hidden` pattern, preview-only): editable parameter form, live known-answer verdict (centerpiece), custom test vector, live JSON preview, Load/Save through the E5 loader, multi-range coverage strip with per-policy CRC preview, gap-conflict surfacing, and a preview-only guard.

**Out of scope (unchanged from the design doc §9)**
- Any write of CRC bytes into firmware (stays in the work-area-contained `CrcOperation` / Flow-Builder CRC block).
- The `operation:"checksum"` discriminator, `serialization.align`, and reflected-form poly entry (design §9 extension points, not built).
- MOD_COMMON module-wide alignment; multi-image scope.
- Any edit to the engine-frozen set (see §2.4).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| KAT | Known-Answer Test — the CRC of the 9 ASCII bytes `"123456789"` (`crc_kernel.KAT_MESSAGE`, `crc_kernel.py:31`); a variant's published `check` value. |
| Template | Reusable, placement-free algorithm math (`CrcTemplate`/`CrcAlgorithm`), serialized as `*.crc.json`. |
| Job | Per-firmware artifact: a resolved algorithm + one or more `CrcTarget` (coverage + serialization). The evolved `crc_config`. |
| Coverage | A target's ordered `ranges` digested under two independent gap policies: `intra_gap` (skip/fill, holes inside a range) × `join` (concat/fill, space between ranges). |
| Serialization | How the result word is stored: `store_width` (bytes) + `store_endianness` (little/big). |
| Preview-only | The view computes and displays CRCs but performs no file or `mem_map` write. |
| Rail screen | A `#screen_*` container carrying `db-screen hidden` classes, shown/hidden by `action_show_screen` (`app.py:5234`) via `SCREEN_CONTAINER_IDS` (`app.py:5174`). |

### 1.4 References
- Design (approved): `docs/crc-algorithm-designer/01-requirements.md`.
- Keel (merged): `s19_app/tui/operations/crc_kernel.py`, `.../crc_designer_model.py` (PR #110, `84180b4`).
- Shipped 32-bit op: `s19_app/tui/operations/crc.py`; flat config loader: `.../crc_config.py`.
- Prototype (throwaway, informative): `prototypes/crc_designer.prototype.py`; UI mock: `prototypes/crc_designer.screen.prototype.html`.
- Stack controls: `docs/engineering-rules.md` (C-13/C-13.1/C-23 geometry; C-22/C-28 snapshot census; C-17 markup safety).
- CLAUDE.md: engine-frozen set; facade convention (a2l facades); TUI orchestration-only rule.

### 1.5 Document overview
§2 overall description + constraints. §3 HLR (EARS). §4 LLR. §5 validation strategy + dual traceability. §6 appendices (glossary, design decisions/keel-vs-design reconciliations, risks, reconciliation log, amendments).

---

## 2. Overall description

### 2.1 Product perspective
The keel (batch-57) shipped a width-general engine and the typed template/job/coverage model, exhaustively unit-tested. Batch-58 exposes that engine to the operator through a new TUI rail screen and closes the three engine gaps the view depends on. The view is orchestration-only (`app.py`), routing compute through the headless `crc_kernel` / `crc_designer_model` primitives — no new math in `app.py`.

### 2.2 Product functions
1. Author a CRC variant from parametric building blocks with **live known-answer verification** on every edit.
2. Check the variant against a **custom test vector** (hex or ASCII).
3. Define a target's **multi-range coverage** and preview its CRC over the loaded image under each gap policy.
4. Surface **gap-safety conflicts** and honor `on_gap_conflict`.
5. **Save/Load** templates as JSON through the collect-don't-abort loader, validating the KAT on save.
6. Engine: big-endian/wider **word codec**; **flat-config up-conversion** + **job serialization**; a **template-loader facade**.

### 2.3 User characteristics
Single role: the **operator** (firmware engineer) already using the s19tui rail. Familiar with CRC parameters and firmware memory layout. No new permissions; the view is read/preview-only.

### 2.4 Constraints
- **Engine-frozen set is OFF-LIMITS (0 diffs):** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`, and the frozen TEST files (`tests/test_engine_unchanged.py`, `tests/test_tui_directionb.py::test_tc031_*`). All batch-58 code lands in `operations/` (non-frozen), a NEW `operations/crc_template.py`, and the TUI view files (`app.py`, `screens_directionb.py`/`rail.py`, CSS) — all non-frozen. New tests land in NEW non-frozen files, never in a frozen test file. (Change-first census, §6.3 R-3.)
- **`app.py` is orchestration-only** (CLAUDE.md): feature logic routes through `operations/` primitives; only UI state machinery lives in `app.py`.
- **Untrusted-render posture (C-17):** every template/file-derived string (name, aliases, error text, diagnostics) rendered in the view uses `markup=False` / explicit `Text`.
- **Geometry (C-13/C-23):** the view honors the existing `width-narrow`/`density-compact` reflow classes; no column measuring. Concrete pane geometry is pilot-measured at Phase 3.
- **Adding a rail item** (`RAIL_ENTRIES`, `rail.py:79`; `SCREEN_CONTAINER_IDS`, `app.py:5174`) is a shared-chrome change → triggers the C-22/C-28 snapshot census (§6.3 R-2).

### 2.5 Assumptions and dependencies
- **A1 — keel is authoritative and correct.** The batch-57 kernel + model are merged and green; batch-58 builds on their public API without modifying them (verified: §probe results below). If a keel symbol named here is later renamed, the binding LLR must be re-reconciled.
- **A2 — E5 module-name reconciliation.** The design doc §6 E5 names a NEW `crc_template.py`; the keel already shipped the loader (`read_template`/`parse_template`/`emit_template`) INSIDE `crc_designer_model.py` (verified `crc_template.py exists: False`, loader symbols present). Decision: US-E5 delivers `crc_template.py` as a thin **re-export facade** (CLAUDE.md a2l-facade convention), so imports read `from ..operations.crc_template import read_template` while the implementation stays single-sourced. No untrusted-loader posture is re-invented. (§6.2 D-1.)
- **A3 — E6 is genuinely incomplete in the keel.** `parse_job` handles the evolved shape only; feeding today's flat `crc_config` returns one structural error (verified), and `emit_job` does not exist (verified `has emit_job: False`). US-E6 adds the flat up-convert branch + `emit_job`.
- **A4 — E4 is genuinely incomplete in the keel.** `crc.py` has no `encode_word`/`decode_word` (verified `False False`); big-endian encode exists only as `crc_designer_model.store_word`, and no big-endian DECODE exists anywhere. US-E4 adds both in `crc.py` (non-frozen).
- **A5 — width guard.** `crc_stream` RAISES `ValueError` for `width ∉ [8,64]` (`crc_kernel.py:125`); `_build_algorithm` rejects the same range (`crc_designer_model.py:436`). The view MUST catch this at the live-compute boundary (collect-don't-abort at the surface), so an out-of-range width surfaces as a warning, never a crash.
- **A6 — Textual-framework fidelity (C-16).** The prototype is Python/HTML. Every interaction assumption (focus, arrow-nav, live-recompute-on-change, per-field reactive) is `assumed — verify in the target framework at Phase 3`; the pilot ATs drive the REAL Textual mechanism (`App.run_test()`), not the prototype.

### 2.6 Source user stories

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-E4 | As the engine, I want a big-endian / wider-field word codec (`encode_word`/`decode_word`) with `encode_le`/`decode_le` kept byte-identical, so that a job's `store_endianness="big"` and padded `store_width` serialize correctly without disturbing every current caller. | Design §6 E4 / R-CRC-DSN-014 | READY |
| US-E5 | As the engine, I want a `crc_template.py` loader facade over the shipped collect-don't-abort template loader, so that the view imports the template read/parse/emit API under the design-doc name without re-inventing the untrusted posture. | Design §6 E5 | READY |
| US-E6 | As the engine, I want `parse_job` to also up-convert today's flat `crc_config` and an `emit_job` serializer, so that existing configs keep working and a whole job round-trips to JSON. | Design §6 E6 / AT-CRC-DSN-012 | READY |
| US-V1 | As the operator, I want an editable form (preset selector + algorithm fields + serialization fields) where selecting a preset populates the form without overwriting the saved library entry, so that I can start from a catalogue variant and tailor it. | Design §7 R-001/006 | READY |
| US-V2 | As the operator, I want the CRC of `"123456789"` recomputed on ANY field change and shown as computed-vs-expected with explicit match / mismatch / no-expected, so that I see instantly whether my variant is correct. | Design §7 R-002 (centerpiece) / AT-016 | READY |
| US-V3 | As the operator, I want to enter a custom test vector (hex or ASCII) and see its computed CRC, so that I can check the variant against a device-supplied reference. | Design §7 R-003 | READY |
| US-V4 | As the operator, I want a live JSON preview of the current template that round-trips, so that I can see and trust the artifact I will save. | Design §7 R-004 | READY |
| US-V5 | As the operator, I want to Load/Save the template through the E5 loader — validating `check == compute("123456789")` on save, rendering warnings markup-safe, and surfacing a load fault as one error not a crash — so that saving is safe and loading a bad file never kills the app. | Design §7 R-005/007 | READY |
| US-V6 | As the operator, I want to define a target's coverage (ordered ranges + `intra_gap` + `join` + `pad_byte`) and, when an image is loaded, preview the CRC over real bytes for the active policy AND the alternative policy alongside, so that each toggle's effect is visible before anything is written. | Design §7 R-008/009 (Variant B) | READY |
| US-V7 | As the operator, I want the view to run `gap_conflict` for a `join="fill"` target against the loaded image and honor `on_gap_conflict` (abort refuses / warn proceeds+diagnostic / ignore silent), so that a wrongly-assumed-erased gap cannot silently diverge the previewed CRC. | Design §7 R-011 (obs #2) | READY |
| US-V8 | As the operator, I want a hard guarantee that the Designer never writes CRC bytes into firmware, so that authoring is side-effect-free. | Design §7 R-010 (scope guard) | READY |

> Note: the tasking brief said "10 stories" but enumerated **11** (E4/E5/E6 + V1..V8). All 11 are specified as listed. Flagged for Phase-2 confirmation.

#### Refinement log (one block per story — condensed)

**US-E4 — word codec** · INVEST ✓✓✓✓✓✓ · user=engine/callers · outcome=`encode_word`/`decode_word` support big-endian + `store_width ≥ ceil(width/8)`; `encode_le`/`decode_le` byte-identical · out of scope: narrowing/truncation policy (unchanged). Path: add to `crc.py:480`-area. Evaluability: big store == MSB-first; little == today's `encode_le` (AT-CRC-DSN-014). Class: READY.

**US-E5 — template loader facade** · INVEST ✓✓✓✓✓✓ · user=engine/view · outcome=`crc_template.py` re-exports `read_template`/`parse_template`/`emit_template`/`CrcTemplate`; collect-don't-abort preserved. Open Q: facade vs relocate — resolved to facade (A2). Evaluability: malformed file → one error, no crash (AT-CRC-DSN-015); round-trip (AT-CRC-DSN-012). Class: READY.

**US-E6 — job up-convert + emit_job** · INVEST ✓✓✓✓✓✓ · user=engine · outcome=flat `crc_config` → internal targets; `emit_job` serializes a `CrcJob`; existing fixtures parse unchanged. Evaluability: `DUMMY_CONFIG_TEXT` parses via up-convert with 0 errors; seed algorithm == `zlib`/`crc32_stream` (AT-CRC-DSN-010); flat→parse→emit→parse identity. Class: READY.

**US-V1 — editable form** · INVEST ✓✓✓✓✓✓ · Evaluability: form shows preset selector + algorithm + serialization fields; selecting a preset populates them; `PRESETS` catalogue unchanged. Class: READY.

**US-V2 — live KAT verdict (centerpiece)** · Evaluability: on a field change, the verdict recomputes `kat` and shows MATCH/MISMATCH/NO-EXPECTED within the same interaction (AT-016 pilot); every preset shows MATCH (AT-CRC-DSN-011). C-16: reactive recompute is `assumed — verify in Textual`. Class: READY.

**US-V3 — custom vector** · Evaluability: entering `0x3132...` or ASCII `123456789` shows computed CRC equal to `kat`. Class: READY.

**US-V4 — live JSON preview** · Evaluability: preview text parses back to an identical typed template (AT-058-04). Class: READY.

**US-V5 — Load/Save + save-KAT + markup-safe** · Evaluability: save refuses/warns when `check != compute("123456789")`; a bracket/ANSI payload in a name renders literally, no crash (AT-058-06, C-17); a malformed load → one error (AT-CRC-DSN-015). Class: READY.

**US-V6 — coverage strip + per-policy preview** · Evaluability: single-range skip==region CRC, fill==pad-filled (AT-CRC-DSN-013); two-range concat==group `0x9C5BCBBD`, fill==`0x2A8A3950` (AT-CRC-DSN-013b); both policy values shown when an image is loaded (AT-058-07). Class: READY.

**US-V7 — gap-conflict** · Evaluability: clean→no conflict, dirty→conflict address surfaced, abort refuses the run (AT-CRC-DSN-017 + AT-058-08). Class: READY.

**US-V8 — preview-only guard** · Evaluability (negative): no view code path calls a file/`mem_map` writer (`emit_s19_from_mem_map`, `copy_into_workarea`, `write_crc_image`, `inject_crcs`, `.write_text`) — AT-058-09. Class: READY.

---

## 3. High-level requirements (HLR)

### HLR-E4 — Big-endian / wider-field word codec
- **Traceability:** US-E4
- **Statement:** The CRC engine shall provide `encode_word(value, *, store_width, endianness)` and `decode_word(data, *, endianness)` that serialize/deserialize a CRC word for `endianness ∈ {"little","big"}` and any `store_width` in 1..8, and shall keep `encode_le`/`decode_le` byte-identical to their current output.
- **Rationale (informative):** a job's `store_endianness="big"` and padded `store_width` need a codec; the existing `encode_le` is little-only and positional.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_crc_word_codec.py`
- **Numeric pass threshold:** exit 0; `encode_word(0x04030201, store_width=4, endianness="big") == b"\x04\x03\x02\x01"`, `... "little" == b"\x01\x02\x03\x04"` (probe-confirmed via `store_word`); `encode_le(v,w) == encode_word(v, store_width=w, endianness="little")` for all `w∈{1,2,4,8}`; `decode_word(encode_word(v,...),...) == v & mask`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** big-endian stores MSB-first; little is byte-identical to today's `encode_le`.
  - **Shipped surface:** `s19_app.tui.operations.crc.encode_word` / `decode_word` (NEW — created in Phase 3).
  - **Deliverable + observation:** the two functions importable and returning the asserted bytes/ints.
  - **Acceptance test(s):** `AT-CRC-DSN-014`.
  - **Boundary catalog:** ☑ empty (`store_width=1`) ☑ boundary (`store_width=8` zero-extend of a 32-bit CRC) ☑ invalid (`store_width < ceil(width/8)` → caller-owed warning, N/A to the codec: codec zero-extends, the *view* warns — US-V5) ☑ error (unknown `endianness` → `ValueError`, caught by callers).

### HLR-E5 — Template-loader facade
- **Traceability:** US-E5
- **Statement:** The engine shall expose a `crc_template.py` module that re-exports the collect-don't-abort template loader (`read_template`, `parse_template`, `emit_template`, `CrcTemplate`) such that a malformed or over-cap or unresolvable template returns `(None, [one error])` and never raises.
- **Rationale (informative):** the design names `crc_template.py`; the loader already exists in `crc_designer_model.py` — a facade reconciles the name without duplicating the posture.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_crc_template_loader.py`
- **Numeric pass threshold:** exit 0; `crc_template.read_template` is the same callable object as `crc_designer_model.read_template`; a bad-JSON / over-cap / missing-field input each returns exactly `len(errors)==1` with `template is None`.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** importing the loader under the `crc_template` name yields the shipped behavior; a malformed file surfaces exactly one error, no crash.
  - **Shipped surface:** `s19_app.tui.operations.crc_template` (NEW facade module — created in Phase 3).
  - **Deliverable + observation:** module file at `s19_app/tui/operations/crc_template.py`, non-empty, re-exporting the four symbols; `read_template("nope.json")` → `(None, [one error])`.
  - **Acceptance test(s):** `AT-CRC-DSN-015`, `AT-CRC-DSN-012`.
  - **Boundary catalog:** ☑ empty (empty file → JSON error) ☑ boundary (over-cap via injected `size_probe`) ☑ invalid (missing `algorithm`) ☑ error (unresolvable path).

### HLR-E6 — Flat-config up-converter + job serializer
- **Traceability:** US-E6
- **Statement:** When given today's flat `crc_config` (`polynomial`/`init`/`reverse`/`final_xor` + `regions`/`groups`), the job parser shall up-convert it into the same internal `CrcJob` target list used by the evolved shape, and the engine shall provide `emit_job(job)` that serializes a `CrcJob` to JSON that parses back to an equal job.
- **Rationale (informative):** back-compat for existing `crc_config.json`; a job artifact must be writable for the view's job authoring.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_crc_job_upconvert.py`
- **Numeric pass threshold:** exit 0; `parse_job(DUMMY_CONFIG_TEXT)` returns `errors == []` (currently returns 1 error — verified pre-state); the up-converted algorithm's `compute(b"123456789") == crc32_stream(b"123456789") == 0xCBF43926`; `parse_job(emit_job(job))[0] == job` for a representative job.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** an existing flat `crc_config` parses without error and computes identically to `crc.compute_group_crc`; a job serializes and round-trips.
  - **Shipped surface:** `crc_designer_model.parse_job` (extended, `crc_designer_model.py:554`) + `crc_designer_model.emit_job` (NEW — created in Phase 3).
  - **Deliverable + observation:** `parse_job(DUMMY_CONFIG_TEXT)` → non-None job, `[]` errors; `emit_job` returns round-tripping JSON text.
  - **Acceptance test(s):** `AT-CRC-DSN-010`, `AT-058-01`.
  - **Boundary catalog:** ☑ empty (no regions and no groups → one error, parity with `crc_config._build_config`) ☑ boundary (a `groups`-only flat config) ☑ invalid (over-`RANGE_COUNT_CEILING`) ☑ error (bad JSON → one error).

### HLR-V1 — Editable parameter form
- **Traceability:** US-V1
- **Statement:** The CRC Designer view shall present the §3 building blocks as an editable form — a preset selector, the `algorithm` fields (`width`/`poly`/`init`/`refin`/`refout`/`xorout`/`check`), and the `serialization` fields (`store_width`/`store_endianness`) — and when a preset is selected shall populate the form from that preset without mutating the `PRESETS` catalogue.
- **Rationale (informative):** presets are read-only starting points; edits save under a new name.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k form_and_preset`
- **Numeric pass threshold:** exit 0. **AT-058-02 (M2 delta gate):** starting from the seed default (CRC-32/ISO-HDLC), select a NON-DEFAULT preset (`CRC-16/MODBUS`) via the mounted selector and assert the form fields TRANSITIONED to MODBUS's values — a measured DELTA vs the seed (`width 32→16`, `poly 0x04C11DB7→0x8005`, `xorout 0xFFFFFFFF→0x0000`), not merely that fields equal a hand-list. The preset set iterates `crc_kernel.PRESETS`; `crc_kernel.PRESETS` is object-unchanged after all selections.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the form renders all named fields; selecting a non-default preset moves them off the seed defaults; the saved catalogue is untouched.
  - **Shipped surface:** `#screen_crc_designer` composed by `_compose_screen_crc_designer` (NEW — created in Phase 3), preset selector wired to `crc_kernel.preset_by_name` (`crc_kernel.py:409`).
  - **Deliverable + observation:** mounted form widgets read via Pilot; the seed→MODBUS field delta observed through the selector.
  - **Acceptance test(s):** `AT-058-02` (seed→non-default preset delta through the mounted selector, M2).
  - **Boundary catalog:** ☑ empty (no preset selected = seed default) ☑ boundary (CRC-64 widest field) ☑ invalid (out-of-range width typed → warning not crash, US-V5/A5) ☑ error N/A (selector values are catalogue-bounded).

### HLR-V2 — Live known-answer verdict (centerpiece)
- **Traceability:** US-V2
- **Statement:** When any algorithm field changes, the view shall recompute the CRC of `"123456789"` and display computed-vs-expected `check` with an explicit `MATCH` / `MISMATCH` / `NO-EXPECTED` state, within the same interaction (no explicit Run).
- **Rationale (informative):** the prototype centerpiece — instant correctness feedback.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k live_verdict`
- **Numeric pass threshold:** exit 0. **AT-CRC-DSN-016 (transition gate, B3):** via Textual Pilot on the MOUNTED screen, capture the verdict widget's rendered content BEFORE a single real field-change event (`Input.Changed` on the field) and AFTER it, with NO Run / `refresh` / re-query action between — assert the content TRANSITIONED (`MATCH → MISMATCH` after breaking `xorout`; and, in a second single event, `MISMATCH → NO-EXPECTED` after clearing `check`). An end-state-only assertion is the defect and fails the intent. **AT-CRC-DSN-011 (M1):** the preset set is derived from `crc_kernel.PRESETS` (assert `len(PRESETS) >= 7`, no hand-typed list); selecting each yields a MATCH verdict read from the mounted widget.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the verdict line updates on edit, showing the tri-state.
  - **Shipped surface:** the verdict widget in `#screen_crc_designer`, driven by `crc_kernel.CrcAlgorithm.kat_ok` (`crc_kernel.py:350`, tri-state `True/False/None`).
  - **Deliverable + observation:** the verdict widget's rendered text read via Pilot BEFORE and AFTER one field-change event (never a headless `kat_ok()` call as the gate).
  - **Acceptance test(s):** `AT-CRC-DSN-011` (preset set from `PRESETS`, M1), `AT-CRC-DSN-016` (before/after single-event transition through the mounted widget, B3).
  - **Boundary catalog:** ☑ empty (`check=None` → NO-EXPECTED) ☑ boundary (CRC-64 width verdict) ☑ invalid (width out of [8,64] → warning, no crash — A5) ☑ error (non-hex field entry → warning, no crash).

### HLR-V3 — Custom test vector
- **Traceability:** US-V3
- **Statement:** The view shall accept a custom test vector as hex or ASCII and shall display the current variant's computed CRC over those bytes.
- **Rationale (informative):** validate a variant against a device-supplied reference.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k custom_vector`
- **Numeric pass threshold:** exit 0; entering ASCII `123456789` and hex `31 32 33 34 35 36 37 38 39` each yield the same displayed CRC equal to `kat()`.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the computed CRC of the entered vector is shown.
  - **Shipped surface:** the custom-vector input + result in `#screen_crc_designer`, computing via `CrcAlgorithm.compute` (`crc_kernel.py:309`).
  - **Deliverable + observation:** rendered CRC of the entered bytes (pilot).
  - **Acceptance test(s):** `AT-058-03`.
  - **Boundary catalog:** ☑ empty (empty vector → CRC of `b""`) ☑ boundary (long vector) ☑ invalid (malformed hex → warning, no crash) ☑ error (odd-length hex → warning).

### HLR-V4 — Live JSON preview (round-trips)
- **Traceability:** US-V4
- **Statement:** The view shall render a live JSON preview of the current template such that the previewed text parses back to an equal typed template.
- **Rationale (informative):** the operator sees and trusts the artifact before saving.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k json_preview`
- **Numeric pass threshold:** exit 0. **AT-058-04 (through-surface gate, B1):** mount the screen via Textual Pilot, make a representative edit through a form field, READ the JSON-preview WIDGET's rendered text (`.query_one("#crc_json_preview")` content, NOT `emit_template(t)` in the test), and assert `parse_template(<that rendered text>)[0] == current_template` with `errors == []`. A headless `parse_template(emit_template(t))` check MAY remain as a SUPPLEMENTARY consumer-contract guard but is explicitly NOT the gate.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the text SHOWN in the preview widget round-trips through the loader.
  - **Shipped surface:** the JSON preview widget (`#crc_json_preview`, NEW — created in Phase 3), fed by `crc_designer_model.emit_template` (`crc_designer_model.py:625`), re-parsed by `parse_template` (`:504`).
  - **Deliverable + observation:** the MOUNTED preview widget's rendered text, read via Pilot and re-parsed; round-trip equality asserted against the widget content, not an in-test emit.
  - **Acceptance test(s):** `AT-058-04` (parse the mounted preview widget's rendered text, B1).
  - **Boundary catalog:** ☑ empty (default seed preview) ☑ boundary (`check=None` emitted as `null`) ☑ invalid N/A (preview is engine-emitted, always valid) ☑ error N/A.

### HLR-V5 — Load/Save with save-time KAT + markup-safe surfacing
- **Traceability:** US-V5
- **Statement:** The view shall Load a template through the E5 loader and Save the current template to the library, and on Save shall validate that `check == compute("123456789")`; a save-time or load-time warning shall render `markup=False`; a load/parse fault shall surface as exactly one error and never crash the app.
- **Rationale (informative):** the standard KAT (obs #3) is the save gate; the file/template text is untrusted (C-17).
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k load_save_and_markup`
- **Numeric pass threshold:** exit 0. **AT-058-05 (through-view Save→Load loop, B2):** drive Save THROUGH the mounted view (press the Save control) → a real `.crc.json` file lands in the template-lib dir → drive Load THROUGH the view on that file → assert every form field equals the originals (round-trip observed via the view, not a headless `parse(emit(t))`). A headless round-trip MAY remain SUPPLEMENTARY, not the gate. **AT-058-10 (three warn conditions, M4):** through the view, assert a warning fires for EACH of: (1) `intra_gap`/`join="fill"` with no `pad_byte`; (2) `store_width < ceil(width/8)` (mandatory — silent detection-strength truncation); (3) `check != compute("123456789")` on Save. **AT-058-06 / AT-CRC-DSN-015 (load fault + markup):** a malformed load → exactly one surfaced error, app alive; a template named `[bold]x[/]` + an ANSI escape renders literally at every sink INCLUDING the JSON-preview widget (see F1 below).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** Save writes a file that Load restores field-for-field; each warn condition surfaces; load faults surface one error; hostile text renders literally everywhere.
  - **Shipped surface:** Load/Save controls in `#screen_crc_designer`, routing through `crc_template.read_template` / `emit_template` (NEW facade), warnings rendered `markup=False`.
  - **Deliverable + observation:** on Save, a real `*.crc.json` under the app template-lib constant dir (basename normalized via `sanitize_project_name`), reloaded through the view; on Load, the surfaced error string; the literal-rendered hostile text at every sink.
  - **Acceptance test(s):** `AT-058-05` (through-view Save→Load loop, B2), `AT-058-10` (three warn conditions, M4), `AT-058-06` (C-17 hostile-input incl. JSON preview, F1), `AT-CRC-DSN-015` (malformed load → one error).
  - **Boundary catalog:** ☑ empty (save with `check=None` → save-KAT skipped, informational) ☑ boundary (name needing normalization; `store_width == ceil(width/8)` → no warn) ☑ invalid (KAT mismatch → warn; `store_width` too small → warn; `fill` with no `pad_byte` → warn) ☑ error (malformed load → one error, no crash).

### HLR-V6 — Coverage strip + per-policy preview
- **Traceability:** US-V6
- **Statement:** The view shall let the operator define a target's coverage — an ordered list of ≥1 `ranges`, the `intra_gap` toggle (skip/fill), the `join` toggle (concat/fill), and `pad_byte` — and, while an image is loaded, shall preview the target's CRC over the real bytes for the active policy and shall show the alternative policy's value alongside.
- **Rationale (informative):** Variant B — the effect of each toggle is visible before anything is written.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k coverage_preview`
- **Numeric pass threshold:** exit 0. **AT-058-07 (oracle-through-the-view, M5):** load the concrete §3.2 fixture image — `mem_map = {0x8000+i: i for i in range(8)} ∪ {0x8010+i: 0x10+i for i in range(8)}`, i.e. two ranges `0x8000-0x8008` + `0x8010-0x8018` with an 8-byte erased gap — set a two-range `join="fill"` target in the coverage strip, and assert the STRINGS rendered by the preview widget contain the oracle hexes `0x9C5BCBBD` (active/alt `concat`) and `0x2A8A3950` (`fill(0xFF)`) — the exact probe-confirmed values, read from the mounted widget, not merely "two numbers render". `AT-CRC-DSN-013`: single-range `skip` == `crc.compute_region_crc`; `fill` == pad-filled CRC.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** both policy CRCs shown over the loaded image, matching the §3.2 oracles.
  - **Shipped surface:** the coverage strip in `#screen_crc_designer`, computing via `crc_designer_model.compute_target_crc` (`:213`) / `gather_target` (`:168`); toggle vocabularies bind to `INTRA_GAP_VALUES` (`:48`) / `JOIN_VALUES` (`:49`).
  - **Deliverable + observation:** the per-policy CRC hex strings READ from the mounted preview widget, asserted equal to `0x9C5BCBBD` / `0x2A8A3950` over the named fixture; the headless oracle is supplementary.
  - **Acceptance test(s):** `AT-CRC-DSN-013`, `AT-CRC-DSN-013b`, `AT-058-07` (§3.2 fixture oracles observed through the mounted view, M5).
  - **Boundary catalog:** ☑ empty (no image loaded → preview shows "no image" note, no compute) ☑ boundary (single range) ☑ invalid (inverted range → caught by `_build_target`, surfaced as warning) ☑ error (>ceiling ranges → one error).

### HLR-V7 — Gap-conflict surfacing + policy honoring
- **Traceability:** US-V7
- **Statement:** Where a target uses `join="fill"`, the view shall run `gap_conflict` against the loaded image, surface any conflicting addresses, and honor `on_gap_conflict`: `abort` shall refuse the preview run (no CRC), `warn` shall proceed with a diagnostic, `ignore` shall proceed silently.
- **Rationale (informative):** obs #2 — a wrongly-assumed-erased gap must not silently diverge the CRC.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k gap_conflict`
- **Numeric pass threshold:** exit 0; a clean gap → 0 conflicts and a CRC; a stray non-`pad_byte` present byte at `0x800A` → conflict `[0x800A]` surfaced; `abort` → refused (no CRC shown); `warn` → CRC + diagnostic; `ignore` → CRC, no diagnostic. (Probe-confirmed: dirty conflict `(32778,)`, abort `refused=True crc=None`.)
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** conflict addresses shown; the run is refused/proceeds per policy.
  - **Shipped surface:** the coverage strip, computing via `crc_designer_model.evaluate_target` (`:348`) / `gap_conflict` (`:241`); policy vocabulary binds `ON_GAP_CONFLICT_VALUES` (`:56`).
  - **Deliverable + observation:** the rendered conflict/diagnostic text and the presence/absence of a previewed CRC.
  - **Acceptance test(s):** `AT-CRC-DSN-017`, `AT-058-08`.
  - **Boundary catalog:** ☑ empty (`join="concat"` never conflicts → `[]`) ☑ boundary (conflict at gap edge) ☑ invalid N/A (policy is enum-bounded) ☑ error (many conflicts → truncated diagnostic, `evaluate_target` shows first 8).

### HLR-V8 — Preview-only guard
- **Traceability:** US-V8
- **Statement:** The CRC Designer view shall not write CRC bytes into firmware nor mutate any `mem_map`; it shall only compute and display CRCs and, on Save, write a `*.crc.json` template under the template library.
- **Rationale (informative):** authoring is side-effect-free; inject/write stays in the work-area-contained `CrcOperation`.
- **Validation:** `inspection` + `test`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k preview_only` (a negative test) + inspection of `_compose_screen_crc_designer` and its handlers for any call to a firmware-write symbol.
- **Numeric pass threshold:** 0 references from the view's code to `emit_s19_from_mem_map`, `copy_into_workarea`, `write_crc_image`, `inject_crcs`, or a `mem_map` mutation; the loaded `current_file.mem_map` is object-unchanged after a full preview interaction.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** no firmware file is produced and the loaded image is unchanged by any Designer action.
  - **Shipped surface:** the whole `#screen_crc_designer` handler set.
  - **Deliverable + observation:** negative AT — after exercising every Designer control, no new firmware artifact exists and `mem_map` is identical.
  - **Acceptance test(s):** `AT-058-09`.
  - **Boundary catalog:** ☑ empty (no image → nothing to write) ☑ boundary (Save writes ONLY a template `.crc.json`, not firmware) ☑ invalid N/A ☑ error N/A.

---

## 4. Low-level requirements (LLR)

### LLR-E4.1 — `encode_word`
- **Traceability:** HLR-E4
- **Statement:** `crc.encode_word(value, *, store_width, endianness)` shall return exactly `store_width` bytes with the low `8*store_width` bits of `value` in the given byte order (`"little"`/`"big"`).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_crc_word_codec.py -k encode_word`
- **Numeric pass threshold:** `encode_word(0x04030201, store_width=4, endianness="big")==b"\x04\x03\x02\x01"`; `... "little"==b"\x01\x02\x03\x04"`; width-8 big zero-extends high 4 bytes to `00`.
- **Acceptance criteria:** matches `crc_designer_model.store_word` (`crc_designer_model.py:290`) semantics; unknown `endianness` raises `ValueError`. Symbol `encode_word` — **NEW — created in Phase 3** in `crc.py` (non-frozen).

### LLR-E4.2 — `decode_word`
- **Traceability:** HLR-E4
- **Statement:** `crc.decode_word(data, *, endianness)` shall decode a big- or little-endian byte sequence of any length 1..8 into an int, inverse of `encode_word`.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_crc_word_codec.py -k decode_word`
- **Numeric pass threshold:** `decode_word(encode_word(v, store_width=w, endianness=e), endianness=e) == v & ((1<<8w)-1)` for all `w∈{1,2,4,8}`, `e∈{little,big}`.
- **Acceptance criteria:** `decode_word` — **NEW — created in Phase 3** (no big-endian decode exists today; `crc.decode_le` at `crc.py:514` is little-only).

### LLR-E4.3 — LE wrappers unchanged
- **Traceability:** HLR-E4
- **Statement:** `encode_le`/`decode_le` shall remain byte-identical, re-expressed as thin wrappers over `encode_word`/`decode_word` with `endianness="little"`.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_crc_engine.py tests/test_crc_operation.py` (existing suites)
- **Numeric pass threshold:** existing CRC engine/operation suites pass unchanged (0 new failures); `encode_le(v,w)==encode_word(v,store_width=w,endianness="little")` for `w∈{1,2,4,8}`.
- **Acceptance criteria:** `encode_le` (`crc.py:480`), `decode_le` (`crc.py:514`) keep signatures; the inject path (`inject_crcs`, `crc.py:987`) renders identical bytes.

### LLR-E5.1 — Facade module
- **Traceability:** HLR-E5
- **Statement:** `s19_app/tui/operations/crc_template.py` shall re-export `read_template`, `parse_template`, `emit_template`, and `CrcTemplate` from `crc_designer_model` without re-implementing the read posture.
- **Validation:** `inspection` + `test (unit)`
- **Executed verification:** `pytest tests/test_crc_template_loader.py -k facade_identity` + inspect the module has no `json.loads`/`resolve_input_path` of its own.
- **Numeric pass threshold:** `crc_template.read_template is crc_designer_model.read_template` (and the other three) — object identity; the module body contains 0 parsing logic.
- **Acceptance criteria:** module — **NEW — created in Phase 3**; source symbols exist at `crc_designer_model.py:504` (`parse_template`) / `:625` (`emit_template`) / `:672` (`read_template`) / `:110` (`CrcTemplate`, A-F2 citation fix).

### LLR-E5.2 — Collect-don't-abort preserved through the facade
- **Traceability:** HLR-E5
- **Statement:** A read of a malformed / over-cap / unresolvable template through `crc_template.read_template` shall return `(None, [one error])` and shall not raise.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_crc_template_loader.py -k collect_dont_abort`
- **Numeric pass threshold:** each of {bad JSON, missing `algorithm`, over-cap via injected `size_probe`, unresolvable path} → `template is None` and `len(errors)==1`; 0 exceptions raised.
- **Acceptance criteria:** reuses `READ_SIZE_CAP_BYTES` (imported at `crc_designer_model.py:34`) and `resolve_input_path` (`:35`); no new cap constant.

### LLR-E6.1 — Flat-config up-convert branch
- **Traceability:** HLR-E6
- **Statement:** When the job JSON lacks `algorithm`/`algorithm_ref`/`targets` but carries the flat keys (`polynomial`,`init`,`reverse`,`final_xor`, and at least one of `regions`/`groups`), `parse_job` shall build a `CrcAlgorithm` from those params (`refin=refout=reverse`, `width=32`, `check=None`) and one `CrcTarget` per region (single range, `intra_gap="skip"`, `join="concat"`, `store_width=4`, `store_endianness="little"`) and per group (its spans as ranges), normalizing into the internal target list.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_crc_job_upconvert.py -k flat_upconvert`
- **Numeric pass threshold:** `parse_job(DUMMY_CONFIG_TEXT)` → `errors==[]` (pre-state verified: currently 1 error); each up-converted target's `compute_target_crc` equals `crc.compute_group_crc` over the same spans; the up-converted algorithm's `compute(b"123456789")==0xCBF43926`.
- **Acceptance criteria:** extends `parse_job` (`crc_designer_model.py:554`, non-frozen); reuses `DEFAULT_POLYNOMIAL` semantics from `crc.py:41`. Vocabulary tokens `"skip"`/`"concat"`/`"little"` all in `INTRA_GAP_VALUES`/`JOIN_VALUES`/`ENDIANNESS_VALUES` (`crc_designer_model.py:48-50`).

### LLR-E6.2 — Existing evolved + fixtures unchanged
- **Traceability:** HLR-E6
- **Statement:** The up-convert branch shall not alter parsing of the evolved shape (`algorithm_ref`/inline + `targets[]`); existing `crc_config.json` fixtures shall parse unchanged.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_crc_designer_model.py tests/test_crc_config.py`
- **Numeric pass threshold:** existing suites pass unchanged (0 new failures); an evolved job and a flat job both yield a `CrcJob`.
- **Acceptance criteria:** the evolved branch (`crc_designer_model.py:593-605`) is untouched behaviorally; the flat branch is reached only when the evolved keys are absent.

### LLR-E6.3 — `emit_job`
- **Traceability:** HLR-E6
- **Statement:** `crc_designer_model.emit_job(job)` shall serialize a `CrcJob` to JSON (inline `algorithm` + `targets[]`, hex-string ints, all `CrcTarget` fields) such that `parse_job(emit_job(job))[0] == job`.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_crc_job_upconvert.py -k emit_round_trip`
- **Numeric pass threshold:** for a job with 2 targets (one `join="fill"`, one `"concat"`), `parse_job(emit_job(job))[0] == job` and `errors==[]`.
- **Acceptance criteria:** `emit_job` — **NEW — created in Phase 3**; mirrors `emit_template` (`crc_designer_model.py:625`) hex/`_hex` idiom (`:620`).

### LLR-V1.1 — Screen scaffold + rail wiring
- **Traceability:** HLR-V1
- **Statement:** The app shall compose a `#screen_crc_designer` container (`db-screen hidden`) via a `_compose_screen_crc_designer` method mounted in `#workspace_body`, shall register `"crc_designer": "screen_crc_designer"` in `SCREEN_CONTAINER_IDS`, shall append `RailEntry("crc_designer", "⊕", "R", "CRC Designer")` to `RAIL_ENTRIES`, and shall add `Binding("0", "show_screen('crc_designer')", "CRC Designer", show=False)` — routed by the EXISTING data-driven `action_show_screen` (no new show-screen handler, since it iterates `SCREEN_CONTAINER_IDS`).
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k routing`
- **Numeric pass threshold:** pressing key `0` (or clicking the CRC Designer rail item) shows `#screen_crc_designer` and adds `hidden` to all other rail screens; the rail active marker moves to `"crc_designer"`.
- **Acceptance criteria:** real edit sites — `SCREEN_CONTAINER_IDS` (`app.py:5174`), `RAIL_ENTRIES` (`rail.py:79`), `action_show_screen` (`app.py:5234`, UNCHANGED — data-driven), the `Binding` list, and the `_compose_screen_flow` pattern (`app.py:2161`). Key `0` chosen as the natural unbound 10th (keys `1`-`9` are exhausted by `RAIL_ENTRIES`); glyph `⊕` (U+2295), ASCII fallback `R`. New method/entry/id/binding — **NEW — created in Phase 3**. **Phase-3 obligations:** the C-22/C-28 snapshot census over every baseline asserting on rail composition/glyphs, and a "nine → ten" sweep of the `rail.py` module docstring + `RAIL_ENTRIES` comment (currently say "nine ordered rail items on keys 1-9", `rail.py:7-9,74`).

### LLR-V1.2 — Form fields + preset population
- **Traceability:** HLR-V1
- **Statement:** The form shall expose editable widgets for `width`/`poly`/`init`/`refin`/`refout`/`xorout`/`check`/`store_width`/`store_endianness` and a preset selector, and selecting a preset shall set those widgets from `preset_by_name(name)` without mutating `PRESETS`.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k form_and_preset`
- **Numeric pass threshold:** after selecting each of the 7 presets, form values equal the preset; `crc_kernel.PRESETS` identity + contents unchanged.
- **Acceptance criteria:** `preset_by_name` (`crc_kernel.py:409`), `PRESETS` (`crc_kernel.py:395`), `CrcAlgorithm` fields (`crc_kernel.py:292-299`). Reactive field wiring — `assumed — verify in Textual (C-16)`.

### LLR-V2.1 — Recompute-on-change verdict
- **Traceability:** HLR-V2
- **Statement:** On any algorithm-field change event, the view shall build a `CrcAlgorithm` from the current fields, compute `kat_ok()`, and render `MATCH`/`MISMATCH`/`NO-EXPECTED` from the `True`/`False`/`None` tri-state — within the same event handler, no separate Run.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k live_verdict`
- **Numeric pass threshold:** via Pilot on the mounted screen, the verdict widget content is captured BEFORE and AFTER a single `Input.Changed` event with no intervening Run/`refresh`: breaking `xorout` transitions `MATCH → MISMATCH`; clearing `check` (a second single event) transitions `MISMATCH → NO-EXPECTED`. The preset sweep iterates `crc_kernel.PRESETS` (`len >= 7`) each reading MATCH from the mounted widget. (End-state-only assertion is a defect, B3.)
- **Acceptance criteria:** `CrcAlgorithm.kat_ok` (`crc_kernel.py:350`, tri-state), `CrcAlgorithm.kat` (`:346`). Status tokens `MATCH`/`MISMATCH`/`NO-EXPECTED` — **NEW display tokens — created in Phase 3** (the tri-state source is the merged `kat_ok`). Live recompute mechanism (reactive on `Input.Changed`) — `assumed — verify in Textual (C-16)`; the AT drives the real event, not a headless call.

### LLR-V2.2 — Compute-boundary fault guard
- **Traceability:** HLR-V2
- **Statement:** If the current fields would raise (width ∉ [8,64], non-hex value), the verdict handler shall catch the fault and render a markup-safe warning rather than propagate the exception.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k verdict_fault_guard`
- **Numeric pass threshold:** entering `width=4` → warning shown, app alive (0 exceptions); `crc_stream` would otherwise raise `ValueError` (`crc_kernel.py:125`, verified).
- **Acceptance criteria:** guards the `ValueError` from `crc_stream`/`_build_algorithm` (`crc_designer_model.py:436`); warning rendered `markup=False` (C-17).

### LLR-V3.1 — Custom vector parse + compute
- **Traceability:** HLR-V3
- **Statement:** The view shall parse the custom-vector input as hex (whitespace-tolerant) or ASCII (a mode toggle or auto-detect), compute `CrcAlgorithm.compute(bytes)`, and display the result; a malformed vector shall render a markup-safe warning, not crash.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k custom_vector`
- **Numeric pass threshold:** ASCII `123456789` and hex `31..39` → identical CRC == `kat()`; malformed hex → warning, 0 exceptions.
- **Acceptance criteria:** `CrcAlgorithm.compute` (`crc_kernel.py:309`). Hex/ASCII input mode — **NEW — created in Phase 3**.

### LLR-V4.1 — Emit + re-parse preview
- **Traceability:** HLR-V4
- **Statement:** The JSON preview widget (`#crc_json_preview`) shall render `emit_template(current_template)`, and the acceptance gate shall parse the text READ FROM THE MOUNTED WIDGET such that `parse_template(<mounted preview text>)[0] == current_template`.
- **Validation:** `test (pilot)` (gate) + `test (unit)` (supplementary)
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k json_preview`
- **Numeric pass threshold:** after a representative edit through a form field, `parse_template(pilot.app.query_one("#crc_json_preview").<rendered text>)[0] == current_template` with `errors==[]`. The in-test `parse_template(emit_template(t))` identity is SUPPLEMENTARY, not the gate (B1).
- **Acceptance criteria:** widget id `#crc_json_preview` — **NEW — created in Phase 3**; `emit_template` (`crc_designer_model.py:625`), `parse_template` (`:504`). Preview auto-refresh on edit — `assumed — verify in Textual (C-16)`.

### LLR-V5.1 — Load through the facade
- **Traceability:** HLR-V5
- **Statement:** The Load control shall route through `crc_template.read_template`; a fault shall surface exactly one markup-safe error and leave the form unchanged.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k load_fault`
- **Numeric pass threshold:** a malformed file → one error rendered, app alive; a valid file → form populated.
- **Acceptance criteria:** `read_template` via the E5 facade (LLR-E5.1); error rendered `markup=False`.

### LLR-V5.2 — Save with KAT validation + bounded name normalization + through-view round-trip
- **Traceability:** HLR-V5
- **Statement:** On Save, the view shall write `emit_template(current_template)` to `<TEMPLATE_LIB_DIR>/<sanitized-basename>.crc.json` — where the DIRECTORY is a fixed app template-lib constant and ONLY the basename is name-derived (bounded write, F3) — shall compute `compute("123456789")` and warn (not block) when it differs from the template's `check` (when `check` is set), and when `sanitize_project_name(name)` yields `None`/empty (all-symbol or empty name) shall warn and write NOTHING (no `None.crc.json`, no crash — F2). A subsequent Load of that file through the view shall restore every form field (the B2 gate loop).
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k save_kat_and_roundtrip`
- **Numeric pass threshold:** Save (matching `check`) → file written under the lib-constant dir, no warning → Load through the view → all form fields equal the originals (B2 loop). Save (mismatched `check`) → warning, file still written. Save (name `"@@@"`/empty → sanitize `None`) → 0 files written, one warning, app alive (F2). Basename never escapes the lib dir (F3).
- **Acceptance criteria:** `emit_template` (`crc_designer_model.py:625`); `sanitize_project_name` is the existing `workspace` normalizer (cited in the s19_app CLAUDE.md workspace section) — bind `file:line` at Phase 3, flagged `assumed — verify symbol at Phase 3`; the template-lib dir is a fixed constant — `assumed — define/verify at Phase 3`. The KAT (obs #3) uses `CrcAlgorithm.kat` (`crc_kernel.py:346`), never a memory result.

### LLR-V5.3 — Markup-safe untrusted text — EXHAUSTIVE sink enumeration (C-17, F1)
- **Traceability:** HLR-V5
- **Statement:** EVERY view sink that renders template/file-derived text shall render it `markup=False` (or via an explicit non-interpolated `Text`), so a bracket/ANSI payload renders literally with no style leak and no crash. The exhaustive sink set is: (1) the template **`name`** field; (2) the **`aliases`** list; (3) **loader error** strings; (4) **gap-conflict addresses / diagnostics**; (5) **preset labels** in the selector; and (6) the **JSON-preview widget** (`#crc_json_preview`) — the highest-risk sink, since `emit_template` embeds the hostile `name`/`aliases` verbatim into the previewed JSON.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k markup_safe`
- **Numeric pass threshold:** a template named `[bold]x[/]` plus an ANSI escape in `name`/`aliases` renders as the LITERAL characters at every one of the six sinks — **explicitly including the JSON-preview widget** (F1): assert the preview widget's rendered `plain` text contains the bracket/escape verbatim AND has NO style spans applied (`spans == []`), not merely "no crash"; 0 exceptions.
- **Acceptance criteria:** consistent with `TargetEvaluation.diagnostics` "plain text, no file-derived text" note (`crc_designer_model.py:337`). Six render sites incl. `#crc_json_preview` — **NEW — created in Phase 3**.

### LLR-V5.4 — Save warn conditions (all three) (M4)
- **Traceability:** HLR-V5
- **Statement:** On Save (or on the relevant field change), the view shall raise a non-blocking warning for EACH of these three conditions independently: (a) `intra_gap` or `join` set to `"fill"` with `pad_byte` unset; (b) `store_width < ceil(width/8)` (silent detection-strength truncation — mandatory, not cuttable); (c) the template's `check` differs from `compute("123456789")`.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k warn_conditions`
- **Numeric pass threshold:** each of the three conditions, set in isolation, produces exactly its warning; none set → 0 warnings; all warnings render `markup=False` (LLR-V5.3).
- **Acceptance criteria:** `ceil(width/8)` == `CrcAlgorithm.store_bytes` (`crc_kernel.py:305`); `check` compare uses `CrcAlgorithm.kat` (`:346`); `pad_byte`/`fill` semantics from `CrcTarget` (`crc_designer_model.py:69`). Warn surface — **NEW — created in Phase 3**.

### LLR-V6.1 — Coverage editor
- **Traceability:** HLR-V6
- **Statement:** The coverage strip shall let the operator add/remove/order ≥1 `ranges` and set `intra_gap` (skip/fill), `join` (concat/fill), and `pad_byte`, building a `CrcTarget`; an invalid range shall surface a markup-safe warning via the `_build_target` fault path.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k coverage_editor`
- **Numeric pass threshold:** a two-range target constructs; an inverted range → warning, no crash.
- **Acceptance criteria:** `CrcTarget` (`crc_designer_model.py:69`); toggles bind `INTRA_GAP_VALUES`/`JOIN_VALUES` (`:48-49`); validation reuses the `_build_target` rules (`:452`).

### LLR-V6.2 — Per-policy preview over the loaded image
- **Traceability:** HLR-V6
- **Statement:** While `current_file` is loaded, the view shall compute and display the target's CRC for the active `join` policy AND the alternative policy, using `compute_target_crc` over `current_file.mem_map`; while no image is loaded it shall show a "no image" note and compute nothing.
- **Validation:** `test (pilot + unit)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k coverage_preview`
- **Numeric pass threshold:** over the named §3.2 fixture `mem_map = {0x8000+i: i for i in range(8)} ∪ {0x8010+i: 0x10+i for i in range(8)}` (two ranges `0x8000-0x8008` + `0x8010-0x8018`, 8-byte gap), the mounted preview widget's rendered strings contain `0x9C5BCBBD` (`concat`) AND `0x2A8A3950` (`fill(0xFF)`) — asserted THROUGH the widget (M5), not merely two rendered numbers; single-range `skip` == `crc.compute_region_crc`.
- **Acceptance criteria:** `compute_target_crc` (`crc_designer_model.py:213`), `gather_target` (`:168`); reads `LoadedFile.mem_map` (read-only). No-image path is the empty-state class. Oracle hexes probe-confirmed against the merged keel (Appendix P).

### LLR-V7.1 — Gap-conflict evaluation + policy branch
- **Traceability:** HLR-V7
- **Statement:** For a `join="fill"` target the view shall call `evaluate_target(mem_map, algorithm, target)` and render: the conflict addresses; and per `on_gap_conflict` — `abort` shows "run refused" and no CRC, `warn` shows the CRC plus the diagnostic, `ignore` shows the CRC with no diagnostic.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k gap_conflict`
- **Numeric pass threshold:** clean → CRC + 0 conflicts; dirty `0x800A=0x99` → conflict `[0x800A]`; `abort` → `refused`/no CRC (probe: `refused=True crc=None conflicts=(32778,)`); `warn` → CRC + diagnostic; `ignore` → CRC, no diagnostic.
- **Acceptance criteria:** `evaluate_target` (`crc_designer_model.py:348`), `TargetEvaluation` (`:320`), `gap_conflict` (`:241`); policy binds `ON_GAP_CONFLICT_VALUES` (`:56`). Diagnostics rendered `markup=False` (C-17, LLR-V5.3).

### LLR-V8.1 — No firmware-write path (negative)
- **Traceability:** HLR-V8
- **Statement:** No `#screen_crc_designer` handler shall call `emit_s19_from_mem_map`, `copy_into_workarea`, `write_crc_image`, or `inject_crcs`, nor mutate any `mem_map`; the only file write the view performs is a `*.crc.json` template on Save.
- **Validation:** `inspection` + `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k preview_only` + `rg -n "emit_s19_from_mem_map|copy_into_workarea|write_crc_image|inject_crcs" <view handlers>`
- **Numeric pass threshold:** 0 grep hits in the view handler code; after a full preview interaction `current_file.mem_map` is object-identical (`==` and no new keys).
- **Acceptance criteria:** the write symbols exist only on the `CrcOperation` path (`crc.py:987/1155`, `changes/io.py`); the negative AT drives every Designer control and asserts absence of any firmware artifact.

---

## 5. Validation strategy

### 5.1 Methods
- **Layer A (white-box / functional, `TC-NNN`):** unit tests over the engine LLRs (E4/E5/E6) against oracles (`zlib`, `crc32_stream`, `compute_group_crc`, the probe-confirmed values); inspection for the facade + preview-only structural LLRs.
- **Layer B (black-box / behavioral, `AT-NNN`):** Textual Pilot (`App.run_test()`) over the CRC Designer screen for the view stories, and headless artifact/oracle assertions for the engine stories. Every story has ≥1 `AT` through the shipped surface with boundary + negative evidence.
- **C-16:** pilot ATs drive the REAL Textual mechanism (field-change events, rail routing), never the prototype.
- **Testing-strategy check:** `pytest` is the project's ratified runner (`pyproject.toml`); Textual `App.run_test()` is the established pilot idiom (existing `tests/test_tui_app.py`). No new runtime introduced.

### 5.2 Dual-traceability table

**Behavioral chain (black-box) — per user story:**

| US | Observable outcome | Shipped surface | Acceptance test | Observed? |
|----|--------------------|-----------------|-----------------|-----------|
| US-E4 | big MSB-first, little == `encode_le` | `crc.encode_word`/`decode_word` | AT-CRC-DSN-014 | Phase 4 |
| US-E5 | loader under `crc_template` name; malformed → one error | `crc_template` facade | AT-CRC-DSN-015, AT-CRC-DSN-012 | Phase 4 |
| US-E6 | flat config parses; job round-trips; seed == zlib | `parse_job`(ext) + `emit_job` | AT-CRC-DSN-010, AT-058-01 | Phase 4 |
| US-V1 | form renders; preset populates; catalogue intact | `#screen_crc_designer` form | AT-058-02 | Phase 4 |
| US-V2 | verdict updates on edit; tri-state | verdict widget | AT-CRC-DSN-011, AT-CRC-DSN-016 | Phase 4 |
| US-V3 | custom vector CRC shown | custom-vector box | AT-058-03 | Phase 4 |
| US-V4 | JSON preview round-trips | preview widget | AT-058-04 | Phase 4 |
| US-V5 | Save→Load restores fields; 3 warn conditions; load fault one error; hostile text literal at every sink incl. JSON preview | Load/Save controls | AT-058-05, AT-058-10, AT-058-06, AT-CRC-DSN-015 | Phase 4 |
| US-V6 | active + alt policy CRC over image | coverage strip | AT-CRC-DSN-013, AT-CRC-DSN-013b, AT-058-07 | Phase 4 |
| US-V7 | conflict surfaced; policy honored | coverage strip | AT-CRC-DSN-017, AT-058-08 | Phase 4 |
| US-V8 | no firmware write; mem_map unchanged | whole screen | AT-058-09 | Phase 4 |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case | Notes |
|-------------|--------|-----------|-------|
| HLR-E4 / LLR-E4.1/.2/.3 | test (unit) | TC-058-01..03 | codec + LE-wrapper identity |
| HLR-E5 / LLR-E5.1/.2 | inspection + test (unit) | TC-058-04..05 | facade identity + collect-don't-abort |
| HLR-E6 / LLR-E6.1/.2/.3 | test (unit) | TC-058-06..08 | up-convert + fixtures + emit round-trip |
| HLR-V1 / LLR-V1.1/.2 | test (pilot) | TC-058-09..10 | routing + form/preset |
| HLR-V2 / LLR-V2.1/.2 | test (pilot) | TC-058-11..12 | live verdict + fault guard |
| HLR-V3 / LLR-V3.1 | test (pilot) | TC-058-13 | custom vector |
| HLR-V4 / LLR-V4.1 | test (unit+pilot) | TC-058-14 | preview round-trip |
| HLR-V5 / LLR-V5.1/.2/.3/.4 | test (pilot) | TC-058-15..18 | load / save+roundtrip / markup(6 sinks) / 3 warn conditions |
| HLR-V6 / LLR-V6.1/.2 | test (pilot+unit) | TC-058-19..20 | coverage editor + §3.2-oracle preview |
| HLR-V7 / LLR-V7.1 | test (pilot) | TC-058-21 | gap-conflict policy |
| HLR-V8 / LLR-V8.1 | inspection + test | TC-058-22 | preview-only negative |

> `TC-NNN`/`AT-NNN` file paths, `-k` selectors, and node ids are provisional-until-Phase-3 (V-5) and reconciled from the real tree at Phase 4.

### 5.3 Batch acceptance criteria
- 100% of LLRs covered by ≥1 passing TC.
- Every US has ≥1 passing `AT` observing its outcome through the shipped surface, with boundary + negative evidence.
- 0 diffs against the engine-frozen set (`pytest tests/test_engine_unchanged.py` green; the vs-`main` guard passes).
- Full suite green (`pytest -q`); no new failures in existing CRC suites.
- The 3 C-35 draft-time probes remain reproducible (KAT `0xCBF43926`; presets; `concat=0x9C5BCBBD`/`fill=0x2A8A3950`).

---

## 6. Appendices

### 6.1 Extended glossary
See §1.3. Additional: `refin`/`refout` = bit (reflection) endianness (algorithm math); `store_endianness` = byte endianness (serialization) — deliberately distinct (design §3.1).

### 6.2 Relevant design decisions (keel-vs-design reconciliations)
- **D-1 (E5 module name).** Design §6 says NEW `crc_template.py`; keel put the loader in `crc_designer_model.py`. Resolution: `crc_template.py` is a thin re-export **facade** (a2l-facade convention). LLRs bind to the real symbols. No untrusted posture re-invented.
- **D-2 (E4 location).** Big-endian encode exists as `store_word` in the model; the design wants `encode_word`/`decode_word` in `crc.py` with LE wrappers. Resolution: add both in `crc.py` (non-frozen); `store_word` stays as the model-side convenience.
- **D-3 (E6 completeness).** `parse_job` handles the evolved shape only (flat config errors; verified); `emit_job` absent (verified). Resolution: add the flat up-convert branch + `emit_job` — the real remaining engine work.
- **D-4 (rail 10th item).** The rail is a fixed 9-item tuple on keys 1-9. A 10th CRC Designer item + `SCREEN_CONTAINER_IDS` entry is a shared-chrome change; the key/glyph assignment is a Phase-3 layout decision (C-22/C-28 census).

### 6.3 Open risks
- **R-1 (C-16 framework fidelity).** Live-recompute-on-change, focus, arrow-nav, and reactive field wiring are prototype-proven but Textual-unverified — flagged `assumed` on every affected LLR; pilot ATs drive the real mechanism. Residual risk: a Textual reactive pattern differs from the prototype's imperative loop → caught at Phase 3.
- **R-2 (snapshot census, C-22/C-28).** Adding a rail entry drifts the rail glyph/route snapshots and possibly the workspace baselines → a canonical-CI snapshot-regen PR is expected as a closeout (per prior batches). Enumerate every snapshot asserting on `RAIL_ENTRIES`/rail composition at Phase 3.
- **R-3 (frozen-set census, change-first).** Planned files: `crc.py`, `crc_designer_model.py`, NEW `crc_template.py`, `app.py`, `rail.py`, CSS, and NEW test files — none in the frozen set (verified frozen set = `core/hexfile/range_index/validation/a2l/mac/color_policy` + `test_engine_unchanged.py` + `test_tui_directionb.py::test_tc031_*`). New tests land in NEW files. Confirm at the increment gate (A-2: the gate is the completeness guarantee, not the census).
- **R-4 (geometry, C-13/C-23).** The 4-region layout (form / coverage strip / verdict+vector / JSON preview + Load/Save) must fit the boxed rail-screen chrome; pilot-measure BOTH axes at Phase 3, never inherit a full-screen prototype budget.
- **R-5 (`sanitize_project_name` binding).** LLR-V5.2 names an existing workspace idiom cited in CLAUDE.md but not grep-pinned here — `assumed — verify symbol file:line at Phase 3`.
- **R-6 (RK-3 carried).** A `refin≠refout` or non-catalogue variant has no external KAT oracle — supported but KAT-unverified (design §6 note); the view's NO-EXPECTED state is the honest signal.

### 6.4 Phase-1 reconciliation log
No LLR threshold/statement changed at drafting and no LLR was promoted/removed during a reconciliation event — this is an initial draft. No audit table required. (Any Phase-2 change re-opens this section per the parent-HLR re-read rule.)

### 6.5 Requirement amendments (Before / After · Deleted / New)

Phase-2 cross-review (iterate-to-refine) — **9 amendments** applied in place (3 blockers, 3 majors, 3 minors/security). Parent-HLR re-read: no HLR *statement* changed (all edits sharpen the AT/LLR gate wording under the same parent behavior); each parent's Acceptance block was re-read and updated where the AT id/gate description lives. New: LLR-V5.4; AT-058-10. No requirement deleted.

| # | Fix | Before → After | Parent HLR re-read | Body edit landed |
|---|-----|----------------|--------------------|-------------------|
| B1 | AT-058-04 (C-12) | *Before:* gate = headless `parse_template(emit_template(t))`. *After:* gate reads the MOUNTED `#crc_json_preview` widget text via Pilot and parses THAT; headless = supplementary. | HLR-V4 re-read — statement unchanged (behavior identical); Acceptance test line + numeric threshold updated. | HLR-V4 numeric/Acceptance (§3); LLR-V4.1 statement+threshold (§4). |
| B2 | AT-058-05 (C-12) | *Before:* save/load asserted via a round-trip, not through the view. *After:* gate = Save THROUGH view → real `.crc.json` → Load THROUGH view → fields equal originals. | HLR-V5 re-read — statement unchanged; Acceptance updated. | HLR-V5 numeric/Acceptance (§3); LLR-V5.2 statement+threshold (§4). |
| B3 | AT-CRC-DSN-016 (C-16) | *Before:* end-state-only ("verdict reads MISMATCH"). *After:* capture verdict BEFORE+AFTER a single `Input.Changed` event, assert the `MATCH→MISMATCH` / `MISMATCH→NO-EXPECTED` transition, no Run between. | HLR-V2 re-read — statement unchanged; Acceptance + threshold updated. | HLR-V2 numeric/Acceptance (§3); LLR-V2.1 threshold (§4). |
| M4 | Warn conditions | *Before:* only `check` mismatch covered on Save. *After:* all THREE — no-`pad_byte` fill, `store_width < ceil(width/8)`, `check` mismatch — via NEW **LLR-V5.4** + NEW **AT-058-10**. | HLR-V5 re-read — statement already said "validate `check==compute`"; widened Acceptance to name all three; added a decomposed LLR. | New LLR-V5.4 (§4); HLR-V5 Acceptance + boundary (§3); §5.2 both tables. |
| M5 | AT-058-07 | *Before:* "two numbers render", oracle asserted headlessly. *After:* named §3.2 fixture `mem_map`, assert `0x9C5BCBBD`/`0x2A8A3950` strings READ from the mounted preview widget. | HLR-V6 re-read — statement unchanged; Acceptance/threshold updated. | HLR-V6 numeric/Acceptance (§3); LLR-V6.2 threshold (§4). |
| F1 | LLR-V5.3 (C-17) | *Before:* 4 sinks (name/aliases/error/diagnostics), crash-only assertion. *After:* EXHAUSTIVE 6 sinks incl. preset labels + the JSON-preview widget; assert `plain` verbatim AND `spans==[]` at the preview site. | HLR-V5 re-read — statement unchanged; enumeration widened. | LLR-V5.3 statement+threshold (§4); HLR-V5 Acceptance (§3). |
| M1 | AT-CRC-DSN-011 | *Before:* "each of the 7 presets" (hand-count). *After:* preset set derived from `crc_kernel.PRESETS`, `len>=7` guard, no hand-list. | HLR-V2 re-read — no change. | HLR-V2 numeric (§3); LLR-V2.1 threshold (§4). |
| M2 | AT-058-02 | *Before:* "form fields equal the preset" (any preset, no delta). *After:* seed→`CRC-16/MODBUS` DELTA (`width/poly/xorout` changed) through the mounted selector. | HLR-V1 re-read — no change. | HLR-V1 numeric/Acceptance (§3). |
| F2/F3 | LLR-V5.2 (security) | *Before:* `<lib>/<normalized name>.crc.json`, no None branch, dir unspecified. *After:* dir = fixed template-lib constant (bounded write, F3); `sanitize→None` → warn + write nothing (F2). | HLR-V5 re-read — statement unchanged. | LLR-V5.2 statement+threshold (§4). |
| A-F1 | LLR-V1.1 (rail) | *Before:* "add a `RAIL_ENTRIES` item", key/glyph `assumed`. *After:* key `0` + `RailEntry("crc_designer","⊕","R","CRC Designer")` + `Binding("0",…)` + `SCREEN_CONTAINER_IDS` entry; `action_show_screen` unchanged; C-22/C-28 census + "nine→ten" docstring sweep as Phase-3 obligations. | HLR-V1 re-read — no change. | LLR-V1.1 statement+criteria (§4). |
| A-F2 | LLR-E5.1 citation | *Before:* `CrcTemplate` at `:109`. *After:* `:110`. | n/a | LLR-E5.1 criteria (§4). |

The design-doc-vs-keel reconciliations (§6.2 D-1..D-4) remain *bindings to the merged keel*, not amendments.

---

### Appendix P — Draft-time C-35 execution probe (run 2026-07-20 against `84180b4` keel)
All PASS (values cited by the LLRs above):
- KAT CRC-32/ISO-HDLC over `b"123456789"` → `0xCBF43926` (== `zlib.crc32`) — PASS.
- CRC-16/MODBUS → `0x4B37`; CRC-8/SMBUS → `0xF4`; all 7 presets `kat_ok()==True` — PASS.
- §3.2 two-range vector (`0x8000-0x8008` + `0x8010-0x8018`, 8-byte gap): `concat=0x9C5BCBBD` (16 B), `fill(0xFF)=0x2A8A3950` (24 B) — PASS.
- `gap_conflict` clean → `[]`; dirty `0x800A=0x99` → `[0x800A]`; `evaluate_target(abort)` → `refused=True, crc=None, conflicts=(32778,)` — PASS.
- `store_word` big → `04 03 02 01`; little → `01 02 03 04` — PASS. `crc_lut == crc_stream` (MODBUS) — PASS.
- Gaps confirmed: `crc.encode_word/decode_word` absent; `crc_template.py` absent; `parse_job(DUMMY_CONFIG_TEXT)` → 1 error; `emit_job` absent.
