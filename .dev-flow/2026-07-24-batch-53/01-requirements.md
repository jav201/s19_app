# Requirements Document — s19_app — Batch 2026-07-24-batch-53 (FB-P1 · flow.json persistence)

> **Artifact language:** English (dev-flow default; engineering artifact). Normative keyword: `shall`.

---

## 1. Introduction

### 1.1 Purpose
Formalize the requirements for **FB-P1 (batch-53)**: persist a Flow Builder `Flow` to
`.s19tool/workarea/<project>/flows/<name>.json` as **multiple named flows per project**,
reusable across a file and its variants, with a **hardened untrusted loader** and a
**Save / Load / Import UI** on the `FlowBuilderPanel`. The design is pre-approved (Phase-0
plan + colored prototype Artifact, ALL CASES HELD); this document formalizes it into
IEEE-830 + EARS requirements with two-layer traceability. It does not re-derive the design.

### 1.2 Scope

**In scope**
- Serialize a `Flow` → the schema-v1 JSON envelope (all shipped block kinds **plus** the new ref-less report block).
- A hardened, fail-closed, whole-flow load of an **untrusted** `flow.json`: size cap → parse guard → envelope/schema/blocks validation → **every embedded READ ref re-validated through the reused `_resolve_manifest_entry` guard** → write-target shape pre-check; any finding ⇒ reject (never partial).
- Save / Load / Import UI on `FlowBuilderPanel` (operator decision **D1**, surface-1): name strip, Save modal (unified Save/Save-As), Load modal (ListView + Import…), external Import that **copies** into `flows/` via `copy_into_workarea` (never executed in place), and a **quarantine card** that renders a rejected load's findings while current blocks stay intact.
- A new **ReportBlock** (kind `"report"`, ref-less) — operator decision **D2** — that round-trips in `flow.json`.

**Explicitly OUT of scope (flagged, not silently over-scoped — this is a *persistence* batch)**
- **Report-block EXECUTION / content generation.** FB-P1 **models + serializes + load-validates** the report block only. Actually generating report content during `run_flow` (wiring `report_service` into the flow executor, choosing a report format/destination) is deferred to a follow-up (proposed **FB-P1b**). The only executor touch in FB-P1 is a **no-op tolerance** so a report-bearing flow still runs without error (LLR-004.3). See **RB-model** resolution (§6.2).
- Flow **run-time** ref re-validation — already shipped in `run_flow` (`flow_execution_service.py`); load-time validation is defense-in-depth + early feedback, not a replacement.
- Any edit to a frozen-engine module (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`).
- Concurrent CRC-screen realign (separate `/fast-dev-flow`).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Flow | An ordered, named list of typed blocks (`flow_model.Flow`). |
| Block kind | The `kind` discriminator ∈ {`source`,`patch`,`check`,`crc`,`write_out`,**`report`**}. |
| READ ref | A block field naming a project-relative *input* file (`image_ref`/`change_doc_ref`/`check_doc_ref`/`config_ref`) — containment-checked at load. |
| WRITE target | `output_name` (WriteOutBlock) — a work-area *output* filename; shape-pre-checked at load, authority stays `save_patched_image`. |
| Ref-less block | A block with no `*_ref` and no WRITE target — the ReportBlock. |
| Containment guard | `_resolve_manifest_entry` (`variant_execution_service.py:205`): absolute / escape-root / reparse-point triad; no filesystem open. |
| Quarantine card | A bordered `sev-error` card rendered into `#flow_result` listing a rejected load's findings; current blocks stay intact. |
| Fail-closed | Any finding ⇒ `(None, findings)`; an executable pipeline is never partially loaded. |
| Dirty | Blocks changed since the last save/load (name-strip glyph `●`; saved = `✓`). |

### 1.4 References
- `.dev-flow/2026-07-24-batch-53/PLAN.md` — objective, decisions, OQs, landing map, security posture.
- `prototypes/fb_p1_flow_persistence.NOTES.md` — schema v1, validation order V1–V7, rejection battery, UI layouts.
- `prototypes/fb_p1_flow_persistence.DECISIONS.md` — D1 (surface-1 UI), D2 (ref-less report block).
- `prototypes/fb_p1_flow_persistence.prototype.py` — runnable serialize + hardened load; ALL CASES HELD.
- `s19_app/tui/services/flow_model.py` — `Flow` + 5 frozen block dataclasses.
- `s19_app/tui/services/variant_execution_service.py:205` `_resolve_manifest_entry`; `:364` `read_project_manifest` (file gate).
- `s19_app/tui/workspace.py:34` `WorkareaContainmentError`, `:262` `copy_into_workarea`, `:362` `sanitize_project_name`, `:368` `validate_project_files`.
- `s19_app/tui/screens_directionb.py:2588` `FlowBuilderPanel`; `s19_app/tui/app.py:2277` `on_flow_builder_panel_run_requested`, `:1760` `_active_project_dir`, `:2212` `_compose_screen_flow`.
- `docs/engineering-rules.md` — C-7 (service layer Textual-free), C-10 (glyph-primary/colour-secondary), C-17 (untrusted-render / markup-safety), C-30 (restyle-last / no new tokens).

### 1.5 Document overview
§2 overall description + source stories (INVEST/DoR). §3 HLRs with black-box Acceptance blocks (`AT-NNN`). §4 LLRs (incl. the OQ/cap constants + the ReportBlock spec). §5 validation strategy + dual traceability. §6 appendices (design decisions incl. OQ/RB resolutions, risks, reconciliation, assumptions ledger).

---

## 2. Overall description

### 2.1 Product perspective
FB-P1 sits in the TUI service layer. A new **`s19_app/tui/services/flow_persistence_service.py`** (Textual-free, C-7) owns serialize/deserialize/save/load/list. `flow_model.py` gains a `ReportBlock`. Two modals join `screens.py`; the `FlowBuilderPanel` (`screens_directionb.py`) gains a name strip, Save/Load buttons, two messages, a `set_blocks` mount path, and quarantine-card rendering. Two app handlers (`app.py`) mirror the existing Run handler. **No frozen-engine file is touched.** `workspace.py` is not edited — `flows/` is a subdirectory and `validate_project_files` already skips subdirectories (`workspace.py:368`, verified — see §6.6 ledger).

### 2.2 Product functions
1. Serialize a `Flow` (6 kinds) → schema-v1 envelope; save to `flows/<sanitized>.json`.
2. Load `flows/*.json` hardened: fail-closed, whole-flow, containment-re-validated, markup-safe findings.
3. Save/Load/Import UI (surface-1) with dirty tracking, overwrite notice, quarantine card.
4. Model + serialize a ref-less report block (execution deferred).

### 2.3 User characteristics
Single local operator (firmware/calibration engineer) composing repeatable pipelines in the TUI. Trusted at the keyboard; **the `flow.json` they load is NOT trusted** (may be imported from another machine/vendor) — hence the hardened loader.

### 2.4 Constraints
- **C-7:** the persistence service imports stdlib + model only; no Textual.
- **C-17:** every file-derived string (findings, flow name, refs) rendered markup-safe (`safe_text`, `markup=False`) at the UI boundary.
- **C-10:** state reads from glyph first (`●`/`✓`/`✗`), colour is secondary.
- **C-30:** no new colour tokens — inherited Calm-Dark navy/pastel + `sev-*` classes only.
- **Reuse-not-fork:** ref containment MUST call the *same* `_resolve_manifest_entry`; no reimplementation.
- **Windows-first:** absolute-path detection must catch BOTH `PureWindowsPath` and `PurePosixPath` absolutes, and NTFS reparse points (already handled inside the reused guard).

### 2.5 Assumptions and dependencies
- `_resolve_manifest_entry(project_root, raw_entry, context, issues)` exists and appends `MANIFEST-PATH-ESCAPE`/`MANIFEST-BAD-STRUCTURE` findings without opening the path (verified `variant_execution_service.py:205-292`).
- `copy_into_workarea` refuses a destination outside any workarea with `WorkareaContainmentError` (verified `workspace.py:34,262`; prototype hostile-dest case REFUSED).
- `sanitize_project_name` returns `Optional[str]` (`None` for empty/invalid) (verified `workspace.py:362`).
- `Flow.schema_version` defaults to `1` (verified `flow_model.py:189`).
- The report kind is part of the **initial** schema-v1 vocabulary (no prior `flow.json` has shipped to any user — this is the first persistence batch), so introducing it does **not** require a version bump. Adding *fields* later would.
- **If any assumption fails, the batch is invalidated** (particularly the reuse-not-fork guard contract).

### 2.6 Source user stories

> Connextra format. Only `READY` stories proceed to HLR.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-001 | As an operator, I want to **save** the flow I built to a named `flows/<name>.json`, so that I can reuse the same pipeline across a file and its variants. | PLAN §Objective; D1 | READY |
| US-002 | As an operator, I want a `flow.json` I load to be **validated and rejected wholesale if anything is unsafe or malformed**, so that an untrusted/vendor file can never smuggle a path escape, an unknown block, or a malformed pipeline into my session. | PLAN §Security posture; NOTES §2/§3 | READY |
| US-003 | As an operator, I want **Save / Load / Import** controls on the Flow Builder (with dirty tracking and a visible quarantine card on rejection), so that I can manage named flows and see exactly why a bad file was refused without losing my current work. | D1; NOTES §4 | READY |
| US-004 | As an operator, I want **every flow to carry its report block** and have that block persist across save/load, so that a saved pipeline always describes that it produces a report. | D2 | READY |

#### Refinement log

**US-001 — Save named flow**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = operator · outcome = a `flows/<sanitized>.json` on disk that round-trips · why = reuse across variants · out of scope = report content generation.
- **Feasibility:** path = `flow_to_dict` + `save_flow_json` (prototype proven) · deps = `sanitize_project_name` · fits one batch = yes.
- **Evaluability (black-box):** "When the operator presses Save with a built flow, the file `flows/<name>.json` exists on disk, is non-empty, parses as JSON, and carries `schema_version:1` + the built blocks." → AT-001.
- **Classification:** READY.

**US-002 — Hardened load, fail-closed**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = operator · outcome = a safe file loads into blocks; an unsafe/malformed file is rejected wholesale with readable findings · why = untrusted-input safety · out of scope = run-time ref re-validation (already shipped).
- **Feasibility:** path = `load_flow_json` → `dict_to_flow` reusing `_resolve_manifest_entry` (prototype ALL CASES HELD) · deps = the guard · fits one batch = yes.
- **Evaluability (black-box):** "When the operator loads a hostile `flow.json` (absolute ref + unknown kind), the quarantine card renders both findings and the current blocks are unchanged." → AT-003 (negative); "When the operator loads a valid file, the panel shows its blocks." → AT-002.
- **Open questions:** OQ-1 (codes), OQ-2 (existence), OQ-4 (caps) — resolved §6.2.
- **Classification:** READY.

**US-003 — Save/Load/Import UI**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = operator · outcome = name strip + Save/Load buttons + modals + import-copy + quarantine card + dirty-guard · why = manage flows without losing work · out of scope = drag-drop, multi-select.
- **Feasibility:** path = two modals mirroring `SaveProjectScreen`/`LoadProjectScreen`, two app handlers mirroring the Run handler, `set_blocks` · deps = tkinter filedialog (existing pattern), `copy_into_workarea` · fits one batch = yes (UI is the largest slice; splits cleanly per increment).
- **Evaluability (black-box):** "When the operator imports an external file, it is copied under `flows/` and appears in the list (never loaded in place)." → AT-004; "When Load is invoked over a dirty flow, a discard-confirm modal appears; Cancel keeps the current blocks." → AT-005.
- **Open questions:** OQ-3 (dirty guard) — resolved §6.2.
- **Classification:** READY.

**US-004 — Report block (model + persist)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = operator · outcome = a ref-less `report` block round-trips in `flow.json` · why = "cada flow debe generar su reporte" (the pipeline always describes a report) · **out of scope = generating the report content (deferred FB-P1b).**
- **Feasibility:** path = `ReportBlock` dataclass + `_KIND_SPEC["report"]=(None,{})` ref-less path + `run_flow` no-op tolerance · deps = none new · fits one batch = yes (model + serialize only).
- **Evaluability (black-box):** "When the operator saves a flow containing a report block and reloads it, the panel still shows the report block." → AT-006.
- **Open questions:** RB-model (explicit-optional vs implicit-always + execution scope) — resolved §6.2.
- **Classification:** READY.

---

## 3. High-level requirements (HLR)

### HLR-001 — Serialize a Flow to the schema-v1 envelope
- **Traceability:** US-001
- **Statement:** When the operator saves a flow, the system shall serialize the `Flow` to a schema-v1 JSON envelope `{schema_version:1, name, blocks:[{kind, …}]}` covering all six block kinds and write it to `flows/<sanitize_project_name(name)>.json` under the active project.
- **Rationale (informative):** the model is JSON-ready by shape; a named file is the reuse unit across variants.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -k "serialize or save" ` (path provisional-until-Phase-3, V-5)
- **Numeric pass threshold:** all such TCs pass; round-trip equality holds for 6/6 kinds; `0` failures.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a file `flows/<name>.json` appears on disk, non-empty, valid JSON, `schema_version:1`, blocks match what was built.
  - **Shipped surface:** `FlowBuilderPanel` Save button → `SaveFlowScreen` → app save handler → `save_flow_json`.
  - **Deliverable + observation:** file at `.s19tool/workarea/<project>/flows/<name>.json` — `Path.exists()` ✓, `st_size > 0`, `json.load` succeeds, `payload["schema_version"]==1`, `len(payload["blocks"])` == built count.
  - **Acceptance test(s):** `AT-001`
  - **Boundary catalog (QC-3):** ☑ empty (name sanitizes to `None` → no write, status refuses — TC) ☑ boundary (64-char name, 64 blocks — TC) ☑ invalid (name with only punctuation → sanitize `None`) ☑ error (flows/ dir uncreatable → surfaced, no crash). None N/A.

### HLR-002 — Hardened, fail-closed, whole-flow load of an untrusted flow.json
- **Traceability:** US-002
- **Statement:** When the operator loads a `flow.json`, the system shall validate it in the order size→parse→envelope→schema→blocks→refs→write-target, re-validating every embedded READ ref through `_resolve_manifest_entry`, and if any finding is raised the system shall return `(None, findings)` and load no blocks at all.
- **Rationale (informative):** an executable pipeline must never be partially loaded from untrusted input; reuse-not-fork keeps the containment guarantee identical to run-time.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -k "load or reject or security"` (provisional, V-5)
- **Numeric pass threshold:** all 13 prototype battery cases + the round-trip case pass; `100%` of hostile cases yield `flow is None and len(findings) > 0`; `0` cases open a path or raise.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a valid file loads into the visible blocks list; a hostile file renders a quarantine card with the findings and leaves the current blocks untouched.
  - **Shipped surface:** `LoadFlowScreen` → app load handler → `load_flow_json` → panel `set_blocks` / quarantine render.
  - **Deliverable + observation:** on reject — a `sev-error` card mounted in `#flow_result` containing one line per finding (markup-safe); the blocks list identical to before; the name strip keeps the old name.
  - **Acceptance test(s):** `AT-002` (happy), `AT-003` (hostile — negative)
  - **Boundary catalog (QC-3):** ☑ empty (0-block flow → `FLOW-BAD-STRUCTURE`) ☑ boundary (65 blocks → cap reject; exactly 64 → accept; file at 1 MiB±1) ☑ invalid (absolute ref, `../` traversal, reparse junction, unknown kind, bad enum, strict-key violation, `schema_version` 99 / `"1"` / bool, missing ref) ☑ error (unreadable/oversize/non-JSON file). None N/A.

### HLR-003 — Save / Load / Import UI on the FlowBuilderPanel (surface-1)
- **Traceability:** US-003
- **Statement:** Where the Flow Builder is displayed, the system shall present a name strip (`Flow: <name>` + dirty `●`/saved `✓`) and Save…/Load… buttons on the run row; Save shall open a unified Save/Save-As modal with an overwrite notice; Load shall open a modal listing `flows/*.json` with an Import… control that copies an external file into `flows/` via `copy_into_workarea`; and while the flow is dirty, Load shall present a discard-confirm modal before replacing the blocks.
- **Rationale (informative):** operator decision D1; the quarantine card *renders* the rejection state (a visible card, not a toast) per the signature-element goal.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_flow_persistence_ui.py` via `App.run_test()` pilot (provisional, V-5)
- **Numeric pass threshold:** every UI AT passes; dirty-guard fires on dirty-load and not on clean-load; import lands under `flows/`; `0` failures.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the name strip reflects dirty/saved; Save writes and clears dirty; Import copies then lists; Load-over-dirty prompts.
  - **Shipped surface:** `FlowBuilderPanel` + `SaveFlowScreen`/`LoadFlowScreen` + app handlers.
  - **Deliverable + observation:** rendered elements (name strip glyph, modal widgets, list rows, quarantine card) observed via Pilot query; imported file at `flows/<name>.json` observed on disk.
  - **Acceptance test(s):** `AT-004` (import), `AT-005` (dirty-guard); AT-002/AT-003 also drive this surface.
  - **Boundary catalog (QC-3):** ☑ empty (no saved flows → empty list + Import-only path) ☑ boundary (name collides → overwrite notice; import name collides → `copy_into_workarea` dedup `_<N>`) ☑ invalid (no project loaded → error card, mirror Run) ☑ error (tkinter cancelled / import raises `WorkareaContainmentError` → error card, no crash). None N/A.

### HLR-004 — Ref-less report block: model + serialize + persist (execution deferred)
- **Traceability:** US-004
- **Statement:** The system shall define a frozen `ReportBlock` (kind `"report"`, no `*_ref` and no WRITE target), serialize it as `{"kind":"report"}`, round-trip it through the hardened loader via a ref-less validation path, and tolerate it as a no-op in `run_flow` so a report-bearing flow runs without error.
- **Rationale (informative):** D2 — every saved flow should describe that it produces a report; content generation is deferred (FB-P1b) to keep FB-P1 a persistence batch (RB-model, §6.2).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -k report` + `pytest tests/test_flow_execution_service.py -k report_noop` (provisional, V-5)
- **Numeric pass threshold:** report block round-trips (serialize→load equal); ref-less path adds no ref/write finding; `run_flow` over a report-bearing flow returns a well-formed `FlowRunResult` with `0` errors attributable to the report block.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** a flow with a report block saves, reloads, and still shows the report block; running it does not error on the report block.
  - **Shipped surface:** panel Save/Load + Run.
  - **Deliverable + observation:** reloaded panel blocks list contains the `report` row; `FlowRunResult.block_results` includes a non-error entry for the report block.
  - **Acceptance test(s):** `AT-006`
  - **Boundary catalog (QC-3):** ☑ empty (report block carries no fields) ☑ boundary (report block as sole block; report + 63 others = 64) ☑ invalid (report block with an unknown extra field → `FLOW-BAD-FIELD` strict-keys) ☑ error N/A — a ref-less block has no ref/path failure surface (one-line reason: no external input). 

---

## 4. Low-level requirements (LLR)

### HLR-001 — Serialize

### LLR-001.1 — `flow_to_dict` envelope shape
- **Traceability:** HLR-001
- **Statement:** `flow_persistence_service.flow_to_dict` **NEW — created in Phase 3** shall return `{"schema_version": flow.schema_version, "name": flow.name, "blocks": [ … ]}` with each block emitting `kind` first and field names verbatim from the frozen dataclasses (`image_ref`/`file_type`; `change_doc_ref`; `output_name`/`fmt`; `check_doc_ref`/`gating`; `config_ref`; report → `{"kind":"report"}`).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -t TC-001`
- **Numeric pass threshold:** emitted dict equals the golden envelope for a 6-kind flow; `0` diffs.
- **Acceptance criteria:** all 6 kinds present; unknown model object → `TypeError` (trusted-side).

### LLR-001.2 — `save_flow_json` write under `flows/`
- **Traceability:** HLR-001
- **Statement:** `save_flow_json(flow, raw_name, project_dir)` **NEW** shall compute `clean = sanitize_project_name(raw_name)` (`workspace.py:362`), return `None` when `clean is None`, else create `project_dir/"flows"` (`mkdir parents=True, exist_ok=True`) and write `flows/<clean>.json` as `json.dumps(flow_to_dict(flow), indent=2)` UTF-8, returning the `Path`.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -t TC-002`
- **Numeric pass threshold:** `"Nightly Release!  "` → `flows/NightlyRelease.json` written; empty/punct-only name → `None`, no file; `0` unexpected writes.
- **Acceptance criteria:** identity is the filename; embedded `name` is display-only.

### HLR-002 — Hardened load

### LLR-002.1 — File gate: size probe before parse + parse guard
- **Traceability:** HLR-002
- **Statement:** `load_flow_json(flow_path, project_dir)` **NEW** shall `stat` the file size BEFORE reading and emit `FLOW-SIZE-CAP` when `size > FLOW_SIZE_CAP_BYTES`, then `json.load` catching `JSONDecodeError`/`RecursionError`/`UnicodeDecodeError`/`OSError` → `FLOW-JSON-PARSE`; it shall never raise. Mirrors the `read_project_manifest` file gate (`variant_execution_service.py:364`; exact size-probe/parse-arm lines `assumed ≈427-454 — verify in Phase 3`).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -t TC-003`
- **Numeric pass threshold:** oversize file → `FLOW-SIZE-CAP`, no parse; `{not json` → `FLOW-JSON-PARSE`; unreadable → `FLOW-JSON-PARSE`; `0` exceptions escape.

### LLR-002.2 — V1/V2 envelope + schema-version gate
- **Traceability:** HLR-002
- **Statement:** `dict_to_flow(payload, project_dir)` **NEW** shall emit `FLOW-BAD-STRUCTURE` when `payload` is not a `dict`, and `FLOW-SCHEMA-UNSUPPORTED` unless `payload["schema_version"]` is EXACTLY `int` `1` (`bool` rejected, string `"1"` rejected, absent rejected, future `99` rejected); either finding short-circuits to `(None, findings)`.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -t TC-004`
- **Numeric pass threshold:** `["not","a","dict"]`→`FLOW-BAD-STRUCTURE`; `99`,`"1"`,`True`,absent→`FLOW-SCHEMA-UNSUPPORTED`; exact `1`→pass; `0` misclassifications.

### LLR-002.3 — V3/V4 name + blocks-array bounds
- **Traceability:** HLR-002
- **Statement:** `dict_to_flow` shall emit `FLOW-BAD-FIELD` when `name` is present but not a non-empty `str` ≤ `FLOW_MAX_NAME_LEN`, and `FLOW-BAD-STRUCTURE` when `blocks` is not a list, is empty (`< FLOW_MIN_BLOCKS`), or exceeds `FLOW_MAX_BLOCKS` (the over-cap case short-circuits).
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -t TC-005`
- **Numeric pass threshold:** 0 blocks→`FLOW-BAD-STRUCTURE`; 64→accept; 65→`FLOW-BAD-STRUCTURE`; 65-char name→`FLOW-BAD-FIELD`; 64-char→accept.

### LLR-002.4 — V5 per-block: object · known kind · strict keys · required ref · enums
- **Traceability:** HLR-002
- **Statement:** For each block `dict_to_flow` shall emit: `FLOW-BAD-STRUCTURE` (not an object); `FLOW-UNKNOWN-KIND` (`kind` ∉ `_KIND_SPEC`); `FLOW-BAD-FIELD` for any key outside `{"kind", ref_field?, *enum_fields}` (strict); `FLOW-BAD-FIELD` when a **ref-bearing** kind's required ref is absent/empty/non-str; and `FLOW-BAD-FIELD` when an enum field value ∉ its allowed set (`file_type`/`fmt` ∈ {`s19`,`hex`}; `gating` ∈ {`advisory`,`block-own-op`}). `_KIND_SPEC` **NEW** maps each kind → `(required_ref_field | None, enum_fields)`.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -t TC-006`
- **Numeric pass threshold:** unknown kind `shell`→`FLOW-UNKNOWN-KIND`; `extra_hook`→`FLOW-BAD-FIELD`; missing `image_ref`→`FLOW-BAD-FIELD`; `gating:"chain-kill"`→`FLOW-BAD-FIELD`; `0` misclassifications.

### LLR-002.5 — V6 READ-ref containment through the REUSED guard (OQ-1: MANIFEST-* verbatim)
- **Traceability:** HLR-002
- **Statement:** For each READ ref field (`image_ref`/`change_doc_ref`/`check_doc_ref`/`config_ref`) `dict_to_flow` shall call `_resolve_manifest_entry(project_root, ref, f"{label}.{ref_field}", findings)` (`variant_execution_service.py:205`, imported not forked); a `None` return skips the block, and the guard's own `MANIFEST-PATH-ESCAPE`/`MANIFEST-BAD-STRUCTURE` codes are preserved **verbatim** (OQ-1, §6.2). No filesystem open; existence NOT required (OQ-2, §6.2).
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -t TC-007`
- **Numeric pass threshold:** absolute (win+posix), `../` traversal, and NTFS-junction refs each yield `MANIFEST-PATH-ESCAPE`; a valid relative ref resolves; `0` path opens (assert via no-`FileNotFoundError` on a nonexistent-but-safe ref).

### LLR-002.6 — V7 WRITE-target (`output_name`) shape pre-check
- **Traceability:** HLR-002
- **Statement:** For `output_name` `dict_to_flow` shall emit `FLOW-UNSAFE-OUTPUT-NAME` when it contains `/` or `\`, contains `..`, is absolute, or starts with `.` (hidden); runtime authority stays `save_patched_image` (F-S-01) — this is defense-in-depth, not a new authority.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -t TC-008`
- **Numeric pass threshold:** `..\..\escape.s19`→`FLOW-UNSAFE-OUTPUT-NAME`; `prg_patched.s19`→accept; `0` misclassifications.

### LLR-002.7 — Fail-closed aggregate (never partial)
- **Traceability:** HLR-002
- **Statement:** `dict_to_flow` shall collect all findings and, if any finding exists, return `(None, findings)`; only a finding-free payload returns `(Flow(...), [])`. An executable pipeline is never partially loaded.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -t TC-009`
- **Numeric pass threshold:** a payload with one good + one bad block → `flow is None`; `100%` of the 13-case battery → `flow is None and len(findings) > 0`.

### LLR-002.8 — Findings are markup-safe ValidationIssues (C-17)
- **Traceability:** HLR-002
- **Statement:** Each finding shall be a `ValidationIssue(code, ValidationSeverity.ERROR, message, artifact="flow")` (`validation/model.py`), and every finding message rendered in the quarantine card shall pass through `safe_text` with `markup=False` per line (C-17 / batch-27/43 markup-sink class).
- **Validation:** `inspection` + `test (integration)`
- **Executed verification:** inspect the quarantine render path in `screens_directionb.py` for `safe_text(...)`/`markup=False`; `pytest tests/test_tui_flow_persistence_ui.py -t TC-010` asserts a `[link=…]`-bearing finding message renders as plain text (`.plain` verbatim, `spans == []`).
- **Numeric pass threshold:** injected markup in a finding message never produces a span/link; `0` markup interpretation.

### HLR-003 — UI

### LLR-003.1 — Name strip + dirty tracking (glyph-primary, C-10)
- **Traceability:** HLR-003
- **Statement:** `FlowBuilderPanel` **shall** render a name strip `Flow: <safe_text(name)>` with a state glyph `●` (dirty) / `✓` (saved), set dirty on any block add/clear/edit since the last save/load and clear it on save/load. Glyph is primary; `sev-neutral`/`sev-warning` is secondary (C-10). Name strip widget id **NEW — created in Phase 3**.
- **Validation:** `test (e2e pilot)`
- **Executed verification:** `pytest tests/test_tui_flow_persistence_ui.py -t TC-011`
- **Numeric pass threshold:** add block → `●` visible; save → `✓`; `0` colour-only state cues.

### LLR-003.2 — SaveFlowScreen (unified Save/Save-As + overwrite notice)
- **Traceability:** HLR-003
- **Statement:** `screens.SaveFlowScreen` **NEW** shall present one `OsClipboardInput` prefilled with the current flow name (editing = Save-As), a sanitiser hint, a live `(overwrites existing)` notice when `flows/<sanitize_project_name(input)>.json` already exists, and Save/Cancel; Save posts a `SaveRequested` message and the app writes via `save_flow_json`, then the panel shows `✓ saved flows/<name>.json`. Mirrors `SaveProjectScreen` (`screens.py:~438`, `assumed — verify in Phase 3`).
- **Validation:** `test (e2e pilot)`
- **Executed verification:** `pytest tests/test_tui_flow_persistence_ui.py -t TC-012`
- **Numeric pass threshold:** existing-name → overwrite notice shown; new name → not shown; save writes the file; `0` writes on Cancel.

### LLR-003.3 — LoadFlowScreen (ListView of flows + Import…/Load/Cancel)
- **Traceability:** HLR-003
- **Statement:** `screens.LoadFlowScreen` **NEW** shall list `flows/*.json` stems (via a `list_saved_flows` **NEW** service call) in a `ListView` with Import…/Load/Cancel; Load posts `LoadRequested(stem)`. Mirrors `LoadProjectScreen` (`screens.py:~615`, `assumed — verify in Phase 3`).
- **Validation:** `test (e2e pilot)`
- **Executed verification:** `pytest tests/test_tui_flow_persistence_ui.py -t TC-013`
- **Numeric pass threshold:** N saved flows → N rows (stems, `safe_text`); empty dir → empty list + Import path usable.

### LLR-003.4 — Import copies external file into `flows/` (never in place)
- **Traceability:** HLR-003
- **Statement:** Import… shall open a tkinter filedialog, then call `copy_into_workarea(picked, project_dir/"flows")` (`workspace.py:262`), refresh the list with the imported entry, and never load the external file in place; a `WorkareaContainmentError` (or any raise) renders an error card, not a crash.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -t TC-014` (service-level copy + dedup) and pilot `-t TC-015` (surface).
- **Numeric pass threshold:** external file copied to `flows/`, `imported.parent == project_dir/"flows"`; name collision → dedup `_<N>`; hostile dest → `WorkareaContainmentError` (prototype: REFUSED).

### LLR-003.5 — Quarantine card (renders findings; blocks untouched)
- **Traceability:** HLR-003
- **Statement:** On a rejected load the app shall mount a bordered `sev-error` card into `#flow_result` (`screens_directionb.py:2684`) listing every finding (`safe_text`, `markup=False` per line) with a header `✗ LOAD REJECTED — flows/<name>.json (<n> findings)` and a `Current flow unchanged.` footer; `set_blocks` **NEW** is NOT called, so the blocks list and name strip are unchanged.
- **Validation:** `test (e2e pilot)`
- **Executed verification:** `pytest tests/test_tui_flow_persistence_ui.py -t TC-016`
- **Numeric pass threshold:** hostile load → card with `n` finding lines; `#flow_blocks` identical pre/post; `0` block mutations.

### LLR-003.6 — Dirty-guard confirm modal on Load-over-dirty (OQ-3)
- **Traceability:** HLR-003
- **Statement:** While the flow is dirty (`●`), when Load is confirmed the system shall present a discard-confirm modal before replacing the blocks; on Cancel the current blocks are kept, on Confirm the load proceeds. When not dirty (`✓`), Load proceeds without the modal. (OQ-3, §6.2.)
- **Validation:** `test (e2e pilot)`
- **Executed verification:** `pytest tests/test_tui_flow_persistence_ui.py -t TC-017`
- **Numeric pass threshold:** dirty + Load → modal shown, Cancel keeps blocks; clean + Load → no modal; `0` silent block loss when dirty.

### LLR-003.7 — App handlers + `set_blocks` (mirror the Run handler)
- **Traceability:** HLR-003
- **Statement:** `S19TuiApp` shall gain `on_flow_builder_panel_save_requested` and `on_flow_builder_panel_load_requested` **NEW** mirroring `on_flow_builder_panel_run_requested` (`app.py:2277`): base dir = `_active_project_dir()` (`app.py:1760`); a no-project state renders an error card (as Run does); load routes a valid `Flow` to `panel.set_blocks(flow)` **NEW** and a rejection to the quarantine card.
- **Validation:** `test (e2e pilot)`
- **Executed verification:** `pytest tests/test_tui_flow_persistence_ui.py -t TC-018`
- **Numeric pass threshold:** no project → error card on both Save and Load; valid load → blocks mounted; `0` unhandled exceptions.

### HLR-004 — Report block

### LLR-004.1 — `ReportBlock` model (ref-less, field-less v1)
- **Traceability:** HLR-004
- **Statement:** `flow_model.py` shall gain `BLOCK_REPORT = "report"` **NEW** and a frozen `ReportBlock` **NEW** with `kind: str = BLOCK_REPORT` and **no other fields** (no `*_ref`, no WRITE target), added to the `FlowBlock` union. (No version bump — report is part of the initial v1 vocabulary, §2.5.)
- **Validation:** `inspection` + `test (unit)`
- **Executed verification:** inspect `flow_model.py` for the frozen ref-less dataclass; `pytest tests/test_flow_persistence_service.py -t TC-019`.
- **Numeric pass threshold:** `ReportBlock()` constructs with `kind=="report"` and no ref attribute; `0` extra fields.

### LLR-004.2 — Serialize + ref-less load path for report
- **Traceability:** HLR-004
- **Statement:** `flow_to_dict` shall emit `{"kind":"report"}` for a `ReportBlock`; `_KIND_SPEC["report"] = (None, {})` and `dict_to_flow` shall, when the required-ref field is `None`, skip the required-ref check, V6 (no READ ref), and V7 (no WRITE target), enforcing only strict-keys `{"kind"}`; the report block round-trips equal.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_flow_persistence_service.py -t TC-020`
- **Numeric pass threshold:** serialize→load of a report-bearing flow equal; `{"kind":"report","x":1}`→`FLOW-BAD-FIELD`; `0` spurious ref/write findings on the report block.

### LLR-004.3 — `run_flow` no-op tolerance (EXECUTION BOUNDARY — content generation deferred)
- **Traceability:** HLR-004
- **Statement:** `flow_execution_service.run_flow` (`flow_execution_service.py`, `run_flow` `assumed ≈:128 — verify in Phase 3`; **NOT frozen**) shall recognize a `report` block and produce a well-formed `BlockResult` (`BLOCK_STATUS_SKIPPED` or `BLOCK_STATUS_NOTICES`) with a summary such as `report generation deferred (FB-P1b)`, threading `(mem_map, ranges)` through UNCHANGED — so a report-bearing flow runs without error. **Report CONTENT generation is explicitly OUT OF SCOPE for FB-P1** (RB-model, §6.2). This adds `flow_execution_service.py` to the touched-file set beyond the original landing map — flagged at the gate.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_flow_execution_service.py -t TC-021`
- **Numeric pass threshold:** `run_flow` over `[source, report]` → `FlowRunResult` with `len(block_results)==2`, report entry non-`error`, image ranges unchanged by the report block; `0` errors attributable to the report block.

---

## 5. Validation strategy

### 5.1 Methods
- **Layer A — white-box (`TC-NNN`):** `test (unit)` for the pure service (serialize/deserialize/validators/caps), `test (integration)` for guard-reuse + copy + run_flow tolerance, `inspection` for the ref-less model shape and the markup-safe render path.
- **Layer B — black-box (`AT-NNN`):** Textual `App.run_test()` Pilot e2e through the shipped panel/modals + artifact-on-disk inspection for Save. Every story has ≥1 AT with boundary + negative evidence; AT-003 is the fail-closed negative, AT-005 the dirty-guard boundary.
- **Security note:** the loader is the untrusted surface; the 13-case battery from the prototype becomes TCs under HLR-002 and is a Phase-2/Phase-4 security-gate input. `AT-NNN` ids are provisional-until-Phase-3 (V-5).

### 5.2 Dual-traceability table

**Behavioral chain (black-box) — per user story:**

| US | Observable outcome | Shipped surface | Acceptance test | Observed? |
|----|--------------------|-----------------|-----------------|-----------|
| US-001 | `flows/<name>.json` on disk, non-empty, schema v1, blocks match | Panel Save → SaveFlowScreen → save_flow_json | AT-001 | pending Phase 4 |
| US-002 | valid file → blocks shown; hostile file → quarantine card, blocks unchanged | LoadFlowScreen → load_flow_json → set_blocks / quarantine | AT-002, AT-003 | pending Phase 4 |
| US-003 | import copies to `flows/` + lists; dirty-load prompts | Panel + modals + app handlers | AT-004, AT-005 | pending Phase 4 |
| US-004 | report block round-trips + runs no-op | Panel Save/Load + Run | AT-006 | pending Phase 4 |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case | Notes |
|-------------|--------|-----------|-------|
| HLR-001 | test (e2e) | TC-001, TC-002 | serialize + save |
| LLR-001.1 | test (unit) | TC-001 | envelope shape |
| LLR-001.2 | test (unit) | TC-002 | save + sanitiser |
| HLR-002 | test (integration) | TC-007, TC-009 | guard reuse + fail-closed |
| LLR-002.1 | test (unit) | TC-003 | file gate |
| LLR-002.2 | test (unit) | TC-004 | envelope + schema |
| LLR-002.3 | test (unit) | TC-005 | name + blocks bounds |
| LLR-002.4 | test (unit) | TC-006 | kind/keys/ref/enums |
| LLR-002.5 | test (integration) | TC-007 | MANIFEST-* verbatim |
| LLR-002.6 | test (unit) | TC-008 | output_name shape |
| LLR-002.7 | test (integration) | TC-009 | fail-closed aggregate |
| LLR-002.8 | inspection + test | TC-010 | markup-safe findings |
| HLR-003 | test (e2e) | TC-011..TC-018 | UI |
| LLR-003.1 | test (e2e) | TC-011 | name strip / dirty |
| LLR-003.2 | test (e2e) | TC-012 | SaveFlowScreen |
| LLR-003.3 | test (e2e) | TC-013 | LoadFlowScreen |
| LLR-003.4 | test (int+e2e) | TC-014, TC-015 | import copy |
| LLR-003.5 | test (e2e) | TC-016 | quarantine card |
| LLR-003.6 | test (e2e) | TC-017 | dirty guard |
| LLR-003.7 | test (e2e) | TC-018 | app handlers |
| HLR-004 | test (integration) | TC-020, TC-021 | report persist + no-op |
| LLR-004.1 | inspection + test | TC-019 | ReportBlock model |
| LLR-004.2 | test (unit) | TC-020 | ref-less path |
| LLR-004.3 | test (integration) | TC-021 | run_flow no-op |

### 5.3 Batch acceptance criteria
- 100% of LLRs covered by ≥1 passing TC.
- Every user story has ≥1 passing `AT-NNN` observing its outcome through the shipped surface, with boundary + negative evidence.
- `100%` of the 13-case security battery rejects fail-closed (`flow is None and findings`).
- `0` blocker fails; the security PR-review gate is `0-HIGH` (untrusted loader).
- No frozen-engine file diffs vs `main` (engine-unchanged guards green).

---

## 6. Appendices

### 6.1 Extended glossary
See §1.3.

### 6.2 Relevant design decisions — OQ + RB resolutions (recommended; presented at the Phase-1 gate)

- **OQ-1 (finding codes): KEEP `MANIFEST-*` verbatim.** Reuse-not-fork — the codes travel with the guard, no translation layer, truthful provenance (the reader sees exactly which guard fired), and the prototype held this way. Wrapping as `FLOW-REF-*` means intercepting and rewriting the guard's appended findings = a fork-by-mapping-table + maintenance. Mixed taxonomy (`FLOW-*` envelope + `MANIFEST-*` refs) is acceptable and honest. **Risk / one-way-door flag:** codes are public test contract — shipping `MANIFEST-*` then later wrapping would break tests; treat as a soft one-way door. Locked in LLR-002.5.
- **OQ-2 (existence check at load): CONFIRM — containment only, no existence check.** Matches `read_project_manifest` precedent (existence deferred to run via `MF-PATH-UNRESOLVED`), enables authoring a flow before its inputs exist (the reuse-across-variants goal), and `run_flow` re-validates + surfaces missing files. Recommend AGAINST an advisory "ref not present yet" WARN in FB-P1: a soft WARN muddies the binary "any finding ⇒ reject" contract. Locked in LLR-002.5.
- **OQ-3 (dirty guard): confirm-discard modal on Load-over-dirty; silent when clean.** Data-loss prevention, cheap, standard editor UX, reversible. Locked in LLR-003.6.
- **OQ-4 (caps): CONFIRM as test-asserted LLR constants** — `FLOW_MAX_BLOCKS = 64`, `FLOW_MAX_NAME_LEN = 64`, `FLOW_SIZE_CAP_BYTES = 1_048_576` (1 MiB), plus `FLOW_MIN_BLOCKS = 1`. Generous for a small pipeline description; the 1 MiB cap is deliberately tighter than the manifest's 256 MB copy-cap (a flow is a description, not a payload). **Reversibility:** loosening later is backward-compatible; tightening is breaking — these err generous, so the reversible direction is preserved. Locked in LLR-002.1/002.3.
- **RB-model: model the ReportBlock now as a first-class ref-less serializable kind (target semantics = implicit-always); DEFER the "ensure-terminal-report" invariant AND report content generation to FB-P1b.** Rationale + **execution-scope boundary (flagged, not silently over-scoped):**
  - FB-P1 delivers: `ReportBlock` model (LLR-004.1) + serialize/ref-less load (LLR-004.2) + `run_flow` no-op tolerance (LLR-004.3). This makes the schema report-ready and keeps a report-bearing flow runnable.
  - FB-P1 does NOT deliver: auto-appending a report block to every built/loaded flow ("implicit-always" enforcement), nor generating report content (wiring `report_service` into `flow_execution_service`, choosing format/destination). Because execution is deferred, the literal "cada flow debe generar su reporte" behavior cannot be delivered in a persistence batch — delivering it would balloon FB-P1 into the executor and `report_service`. The honest scope is **model + persist now, generate next.**
  - Recommendation to the operator at the gate: approve the deferral (FB-P1 = persistence + no-op tolerance) OR expand the batch to include report execution (larger, touches the executor + `report_service`). Do not silently over-scope.

### 6.3 Open risks
- **R-1 (security, must-hold):** the loader's safety depends entirely on `_resolve_manifest_entry` staying the sole containment authority (reuse-not-fork). Any local reimplementation voids the guarantee. Mitigation: LLR-002.5 mandates the import; a Phase-2 inspection asserts no forked path logic.
- **R-2 (contract):** caps + finding codes become public test contract (OQ-1/OQ-4). Mitigation: documented as contract in §6.2; changes require a §6.5 amendment.
- **R-3 (scope):** LLR-004.3 adds `flow_execution_service.py` to the touched-file set beyond the plan's landing map. Mitigation: flagged here + at the gate; it is non-frozen; still within the ≤5-files/increment budget when isolated to its own increment.
- **R-4 (markup-sink):** file-derived finding text is a markup-injection surface (C-17). Mitigation: LLR-002.8 mandates `safe_text`/`markup=False` per line with a `[link=…]`-payload TC asserting `spans == []`.
- **R-5 (tkinter in tests):** Import… uses a native filedialog. Mitigation: AT drives the service-level `copy_into_workarea` directly and mocks the dialog; the on-disk copy is the observed deliverable.

### 6.4 Phase-1 reconciliation log

Initial authoring: no prior LLR threshold/statement was *changed* at a reconciliation event. The OQ/RB resolutions **set** constants/behaviors for the first time (born here, no parent HLR to re-read). Audit table (body-first — each row's "Body edit landed?" cites the line that now exists):

| Decision ID | What was set | Parent HLR re-read? | Body edit landed? |
|-------------|--------------|---------------------|-------------------|
| D-OQ1 | MANIFEST-* codes verbatim | HLR-002 — no change required (statement already says "re-validating … through `_resolve_manifest_entry`") | LLR-002.5 statement |
| D-OQ2 | no existence check at load | HLR-002 — no change (order statement unaffected) | LLR-002.5 statement + §6.2 |
| D-OQ3 | dirty-guard confirm modal | HLR-003 — statement amended to include "while dirty … discard-confirm modal" | HLR-003 statement + LLR-003.6 |
| D-OQ4 | caps 64/64/1 MiB + min 1 | HLR-002 — no threshold contradiction | LLR-002.1 + LLR-002.3 |
| D-RB | report = model+persist now, execute later | HLR-004 — statement scoped to "model+serialize+round-trip+no-op" | HLR-004 statement + LLR-004.1/.2/.3 + §6.2 |

### 6.5 Requirement amendments (Before / After · Deleted / New)
None at initial draft. Future Phase-4 black-box failures or Phase-3 spec amendments record here.

### 6.6 Draft-time verification ledger (C-15 / C-15.1 / C-35 / C-36)

**Verified symbols (grep-confirmed `file:line`):**
- `_resolve_manifest_entry(project_root, raw_entry, context, issues)` — `variant_execution_service.py:205` ✓; appends `MANIFEST-PATH-ESCAPE`/`MANIFEST-BAD-STRUCTURE`, no fs open, existence not required (read :205-292).
- `read_project_manifest` — `variant_execution_service.py:364` ✓ (function head; exact file-gate lines `assumed ≈427-454 — verify in Phase 3`).
- `WorkareaContainmentError` `workspace.py:34` ✓; `copy_into_workarea` `:262` ✓; `sanitize_project_name` `:362` ✓ (returns `Optional[str]`); `validate_project_files` `:368` ✓ (skips subdirs → `flows/` unaffected).
- `flow_model`: `BLOCK_SOURCE/PATCH/WRITE_OUT/CHECK/CRC` `:23-27` ✓; `WRITE_FMT_S19/HEX` `:30-31` ✓; `CHECK_GATING_ADVISORY/BLOCK_OWN` `:38-39` ✓; `Flow.schema_version=1` `:189` ✓; 5 frozen block dataclasses ✓ (no `ReportBlock` yet — NEW).
- `FlowBuilderPanel` `screens_directionb.py:2588` ✓; `RunRequested` `:2636` ✓; compose yields `#flow_add_row`/`#flow_run_row`/`#flow_result` `:2677-2684` ✓; `safe_text` in use `:2600,2692` ✓.
- `on_flow_builder_panel_run_requested` `app.py:2277` ✓; `_active_project_dir` `:1760` ✓; `_compose_screen_flow` `:2212` ✓.

**Mental execution of the prototype transform against the model:** `flow_to_dict` over a 6-kind flow (adding `ReportBlock→{"kind":"report"}`) then `dict_to_flow` with `_KIND_SPEC["report"]=(None,{})` → ref-less branch skips required-ref/V6/V7, strict-keys `{"kind"}` → round-trips equal; hostile cases (absolute/`..`/junction/unknown-kind/bad-enum/strict-key/schema `99`/`"1"`/bool/missing-ref/oversize/non-JSON) each short-circuit to `(None, findings)`. Consistent with prototype "ALL CASES HELD."

**NEW — created in Phase 3 (not expected to exist):** `flow_persistence_service.py` and all its symbols (`flow_to_dict`, `dict_to_flow`, `load_flow_json`, `save_flow_json`, `list_saved_flows`, `_KIND_SPEC`, `_READ_REF_FIELDS`, all `FLOW_*` codes/caps); `flow_model.BLOCK_REPORT` + `ReportBlock`; `screens.SaveFlowScreen`/`LoadFlowScreen`; `FlowBuilderPanel` name strip + `SaveRequested`/`LoadRequested` + `set_blocks`; `app` save/load handlers.

**Assumed — verify in Phase 3:** `SaveProjectScreen`≈`screens.py:438` / `LoadProjectScreen`≈`:615` modal patterns; `OsClipboardInput` existence; `run_flow`≈`flow_execution_service.py:128`; the manifest file-gate line span 427-454. Test file paths, `-k` selectors, and `AT/TC` node ids are all provisional-until-Phase-3 (V-5) and reconciled at Phase 4.

**Supersession / guard census (change-first):** touched files — `flow_persistence_service.py` (new), `flow_model.py`, `flow_execution_service.py`, `screens.py`, `screens_directionb.py`, `app.py`, `styles.tcss`. **None is in the engine-frozen set** (`core.py`/`hexfile.py`/`range_index.py`/`validation/`/`tui/a2l.py`/`tui/mac.py`/`tui/color_policy.py`) — verified against CLAUDE.md frozen list. `flow_model.py` gains a NEW symbol into an existing non-frozen file (A-3 probe: confirm no allowlist guard freezes `flow_model.py` — `assumed none — verify in Phase 3`). No package-shape/placement/AST guard is implicated (no module moved; new file lands in the existing `services/` package).
