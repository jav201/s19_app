# Post-mortem — s19_app — 2026-05-21-batch-03

**Phase:** 5 — Post-mortem
**Iteration:** 1
**Date:** 2026-05-21
**Batch:** batch-03 — functional Patch Editor + ASAM CDFX (`.cdfx`) read/write
**Branch:** `dev-flow/batch-02-direction-b-restyle` @ `701a849` (shared working tree — batch-02 + batch-03 accumulating uncommitted; owner to split/commit at a logical point)
**Source artifacts:** `state.json` (`decisions_log`), `01-requirements.md`, `02-review.md` (Phase 2 + iteration-2 closure), `03-increments/increment-plan.md` + `increment-001.md` … `increment-011.md`, `04-validation.md`, `design-input/cdfx-research.md`
**Author:** `architect` agent — synthesizing the architecture/process perspective with the QA/quality/metrics evidence from `04-validation.md` (Phase 4, authored by the `qa-reviewer`)

---

## 0. Executive summary

Batch-03 made the Patch Editor a working tool. It added a parameter **change-list** model keyed to A2L characteristic names + array indices (e.g. `PARAMETER[0] : 23`), **type-driven value display**, and **ASAM CDFX (`.cdfx`) read/write/validation** for vCDM interoperability. Unlike batch-02 (a strictly view-layer restyle against a frozen engine), batch-03 **deliberately added a data-processing layer** — a new pure-Python `s19_app/tui/cdfx/` package and a `cdfx_service.py` seam — while keeping the parsing/validation engine byte-frozen. Scope was held to change-list construction + CDFX I/O; applying the change-list to the firmware image, exporting a modified S19, and undo/redo were all out of scope by design.

The batch ran the full V-model dev-flow in 5 phases. Phase 4 closed with a clean gate:

- pytest suite **419 → 611 passing** (net +192 across the batch path), **0 failed, 3 xfailed, 2 skipped, 27 snapshots passed** — reproduced in Phase 4 with zero drift.
- The engine-freeze `git diff main` over `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` is **empty — zero bytes changed**; the CDFX feature is purely additive new files.
- All **47 TC / 8 HLR / 44 LLR** verdict `pass`; all **11 §5.9 acceptance criteria** met.
- Phase 2 raised **28 findings (3 blockers)** — all 28 closed before Phase 3.

| Phase | Iterations | Artifact | Key result |
|---|---|---|---|
| 1 — Requirements | 3 | `01-requirements.md` | 7 US, 8 HLR, 44 LLR, 47 TC; iter 3 closed all Phase-2 findings |
| 2 — Cross-agent review | 2 | `02-review.md` | iter 1: 3 blockers / 10 majors / 15 minors / 1 info; iter 2: all 28 closed, `pass` |
| 3 — Implementation | 11 increments | `increment-plan.md` + `increment-001.md`…`011.md` | +192 tests, engine zero-diff, 9→11 re-plan |
| 4 — Validation | 1 | `04-validation.md` | verdict `pass-with-gaps`; 0 blockers; 4 documentary/residual gaps |
| 5 — Post-mortem | 1 | this document | recommend **close-batch**; queue batch-04 (MEMORY-value editing) + follow-ups |

**Recommendation: `close-batch`.** The deliverable is complete and independently validated; the deferred scope (apply-to-image, export-modified-S19, the owner-requested raw-MEMORY-value editing) and the four documentary/residual gaps are well-scoped follow-up work — most prominently **batch-04**, the owner-requested extension of the Patch Editor to edit raw MEMORY values — not reasons to keep batch-03 open.

---

## 1. Batch summary

### Objective

Per `state.json`: *"Make the Patch Editor functional: a parameter change-list keyed to A2L characteristic names + array indices (e.g. `PARAMETER[0] : 23`), with value display (decimal/hex/ASCII per A2L data type), saved to and loaded from ASAM CDFX (`.cdfx`) calibration-exchange files (vCDM-compatible). SCOPE: change-list construction + CDFX read/write/validation only."* Batch-02 had shipped the Patch Editor as an inert view shell (`R-TUI-027`, `PatchEditorPanel`); batch-03 replaces that shell with a working tool.

### What shipped

- **The `s19_app/tui/cdfx/` package** — a `core`-style pure-Python package, six modules, no Textual import:
  - `changelist.py` — the change-list model: `ChangeListEntry` (fields `parameter_name`, `array_index: Optional[int]`, `value`, resolution status), `ChangeList` with add/edit/remove, `(name, array_index)` entry identity, deterministic ordering.
  - `resolve.py` — parameter resolution against the loaded A2L via the **enriched** pipeline (`parse_a2l_file` → `extract_a2l_tags` → `enrich_a2l_tags_with_values`), with unresolved-name / index-out-of-range / no-A2L states.
  - `display.py` — type-driven value display: decimal + integral-only hex companion for unsigned ints, signed decimal, fractional decimal for IEEE floats, quoted string for `ASCII`-`char_type`.
  - `writer.py` — CDFX write: the CDF 2.0 `MSRSW` backbone, one `SW-INSTANCE` per resolved parameter, array-entry coalescing into a single `VAL_BLK`, `repr()`-precision floats, the `Created with s19_app CDF 2.0 Writer` tool note, and the work-area-contained `write_cdfx_to_workarea` path.
  - `reader.py` — CDFX read: namespace-tolerant, instance-tree-scoped `SW-INSTANCE` lookup, `V`/`VG`/`VT` decode, `VAL_BLK`→array-entry expansion, the `R-*` validation rule set, A2L cross-checks, plus the XML-safety layer (DOCTYPE/`<!ENTITY>` rejection, 256 MB cap, nesting-depth bound, load-path resolution).
  - `__init__.py` — the narrow public re-export surface.
- **`s19_app/tui/services/cdfx_service.py`** — a thin orchestration service owning one `ChangeList`, mirroring the `a2l_service` pattern; keeps `app.py` free of XML/model logic.
- **The functional Patch Editor screen** — `PatchEditorPanel` rebuilt in `screens_directionb.py` from the inert before/after hex shell into a working editor: a change-list `DataTable`, wired name/index/value `Input`s, add/edit/remove and save/load actions, a `.cdfx` path input, and a neutral empty state. `app.py` gained UI-state wiring only.
- **CDFX validation** — 8 `W-*` structural rules + 2 writer-behavior codes (`W-INSTANCE-EXCLUDED`, `W-ARRAY-SPARSE`) + 9 core `R-*` rules + 2 cross-check codes, every finding a `ValidationIssue` with `artifact="cdfx"` under the existing collect-don't-abort contract.

### What did not ship (deferred by design — user-confirmed scope)

Applying the change-list to the firmware image / memory map; exporting a modified S19 / Intel HEX file; undo/redo history; XSD schema-level validation (validation is structural-only); multi-dimensional `MAP`/axis/structured types and arrays-of-parameters (read-tolerated only). These are carried to follow-up batches — see §7, most prominently the owner-requested **batch-04**.

---

## 2. What worked

### 2.1 The `core`-style pure-Python `cdfx/` package boundary (architecture)

The single highest-leverage architectural decision was placing the change-list model and the CDFX handler in a dedicated package `s19_app/tui/cdfx/`, peer to `tui/a2l.py` / `tui/mac.py`, with **no Textual import anywhere in it** and a thin `cdfx_service.py` seam between it and the UI. This kept the entire data-processing layer fully unit-testable in isolation: increments 5–8 migrated and extended library code that was *not yet reachable from the UI* — the app ran unchanged and the suite stayed green between every one of those increments. The carve-out also made the `app.py` containment of constraint C-8 trivially verifiable: TC-028's inspection found zero `xml.`/`ElementTree` references in `app.py` and confirmed the Patch Editor action handler routes through `self._cdfx_service`. A "data logic lives outside `app.py`" claim is easy to assert; the package boundary made it true by construction.

### 2.2 The layered increment arc — model → resolve → display → writer → reader → safety → UI (architecture)

The increment sequence followed a strict dependency order: change-list model (inc 1) → A2L resolution (inc 2) → type-driven display (inc 3) → writer (inc 4) → `Optional[int]` migration (inc 5) → writer coalescing rework (inc 6) → reader (inc 7) → XML-safety + path containment (inc 8) → functional screen (inc 9) → round-trip hardening (inc 10) → integration tests (inc 11). Each increment consumed only what earlier increments delivered, each left a runnable `s19tui` and a green suite, and the single increment that mutated running UI behaviour (inc 9) was correctly isolated and last-but-three. The ≤5-files-per-increment cap held on every one of the 11 increments — inc 8, 9 and 10 each landed at exactly 5 files, disclosed and counted.

### 2.3 The empirically-verified A2L-enriched-pipeline resolution (architecture)

Phase-2 finding A-01 caught that the original requirement pointed parameter resolution at bare `extract_a2l_tags`, whose `CHARACTERISTIC` tags carry `datatype=None` — the decode-relevant fields are populated only after `enrich_a2l_tags_with_values`. The fix made the *enriched* pipeline (`parse_a2l_file` → `extract_a2l_tags` → `enrich_a2l_tags_with_values`) the normative reuse contract in constraint C-1. TC-004 confirms resolution runs the enriched pipeline with no A2L re-parse. This is the kind of "reuse the existing module" requirement that fails silently if the wrong pipeline stage is named — catching it in review rather than in implementation saved an increment of rework.

### 2.4 The security review catching the write-path containment gap and the DOCTYPE-rejection mitigation (architecture + security)

The Phase-2 security-reviewer pass produced the batch's most consequential pre-implementation findings. **S-001** caught that the `.cdfx` *write* path had no path-containment / traversal / symlink / overwrite requirement at all — A-6/OQ-3 had scoped `.cdfx` out of `validate_project_files` without replacing the guarantee that scoping removed. The fix (LLR-007.7) brought the write path to full `copy_into_workarea` containment parity, reusing the hardened `workspace.py` helpers rather than inventing a new write path. **S-004** caught that "entity expansion disabled OR safely bounded" described a mitigation the stdlib `xml.etree` does not provide — stdlib still expands internal entities unboundedly. The resolution (LLR-006.6) mandated the concrete stdlib-only answer: **reject any `.cdfx` carrying a `DOCTYPE`/`<!ENTITY>` declaration** via an `expat`-level `StartDoctypeDeclHandler` that fires *before* any entity is declared or expanded, neutralizing both billion-laughs and external-entity vectors with one rule and **no `defusedxml` dependency** (preserving C-2). Increment 8 implemented exactly this; TC-027a/b pin it deterministically (no `lollol` expansion text anywhere; the external sentinel marker absent from every parsed value).

### 2.5 The engine verified untouched at zero diff (architecture + QA)

Although batch-03 added a real data-processing layer, the parsing/validation engine was held frozen. The Phase-4 `git diff main` over `core.py`, `hexfile.py`, `range_index.py`, the entire `validation/` directory, `tui/a2l.py` and `tui/mac.py` returned **empty output — zero bytes changed**. Notably, even the anticipated `validation/model.py` edit (Q-12 foresaw `artifact="cdfx"` possibly touching the model) was **not needed** — the `ValidationIssue.artifact` field was already a free-form `str`, so the CDFX feature passes the existing model the new tag with no model change. The whole `cdfx/` package and all 12 test files are new untracked files: the feature is purely additive, and the no-regression criterion holds at the strictest possible level.

### 2.6 Suite 419 → 611 with zero regressions (QA)

The suite grew from the batch-02 419-pass baseline to **611 passing** across the batch-03 path, **0 failed throughout**. The CDFX + Patch Editor subset alone (12 test files) is **192 passed / 0 failed**; the `-m snapshot` subset re-matches all 27 committed baselines. Every one of the 44 LLR maps to ≥1 passing TC; all 11 §5.9 acceptance criteria are met — including the security gate (TC-027a/b), the round-trip gate (TC-024, exact float `==` on three adversarial IEEE binary64 values with no tolerance), and the C-2 / C-9 / no-regression gates. TC-024 is genuinely non-tautological: the denormal `5e-324` and the 17-significant-digit fixture fail under any lossy `str()`/`%g` writer.

---

## 3. What didn't / friction

### 3.1 Three Phase-2 blockers forced a rollback to Phase 1

Phase-2 iteration 1 surfaced **3 blockers**, each a specification defect that made the artifact unverifiable or unsafe as written, and the dev-flow forced a rollback to a Phase-1 iteration 3:

- **Q-01 — the LLR count was arithmetically wrong.** The document stated `34 LLRs`; the real count summed to **39**. The §5.7 reverse-traceability claim and the §5.9 acceptance-gate denominator were both measured against a wrong total — the coverage contract could not be evaluated. (Iteration 3 then corrected it to 39; the Phase-3 amendment later raised it to the final 44.)
- **Q-02 — the entity-bomb fixture was non-executable.** `make_entity_bomb_cdfx` was specified to carry *two* distinct attack payloads (billion-laughs + external-entity) in one fixture while TC-027 asserted a single issue; the "no external file read" clause had no stated detection mechanism. The fix split it into two single-vector fixtures with a concrete sentinel-file no-read check.
- **S-001 — the write-path containment gap** (see §2.4).

None of the three was an implementation impossibility — all were closable with focused requirements edits — but they cost a full Phase-1 iteration plus a Phase-2 closure pass.

### 3.2 The array-mapping gap caught only in Phase 3 increment 4 — the most instructive defect

The change-list model shipped in increment 1 keyed entries by `(parameter_name, array_index)` with `array_index: int` defaulting to `0`. This made a **scalar entry and element 0 of a single-element array indistinguishable** — both are `(name, 0)`. When increment 4 built the writer, it surfaced that the model **could not even express the fix**: the writer cannot decide whether to emit a scalar `VALUE` `SW-INSTANCE` with a bare `V` or a `VAL_BLK` `SW-INSTANCE` with a `VG`, and the standard ASAM CDF 2.0 representation of an array (one `SW-INSTANCE` per parameter, not per element) was unreachable. Increment 4's review packet §5 explicitly flagged the structural divergence and escalated to `architect`.

The architect resolution was a **Phase-3 requirements amendment**: `array_index` became `Optional[int]` (`None` ≙ scalar/string, integer ≙ array element *k*), giving the writer and reader an unambiguous discriminator; two new LLRs were added — **LLR-004.9** (writer coalesces array-element entries into one `VAL_BLK`, rejects sparse arrays) and **LLR-005.6** (reader expands `VAL_BLK` back into array-element entries). This **reopened the already-shipped increment 1** (`changelist.py`), rippled to `resolve.py` and `writer.py`, and forced a **9 → 11 increment re-plan**: a dedicated `Optional[int]` migration increment (5) and a dedicated writer-coalescing increment (6) were inserted, renumbering the tail. Root-cause analysis in §6.

### 3.3 `ruff` and `pytest-textual-snapshot` not pre-installed

`ruff` was absent from the Phase-3/Phase-4 environment for **all 11 increments**; each increment substituted `python -m py_compile` on every changed Python file and recorded `ruff` as a pending item. The mitigation (every module compiles, the 192-pass CDFX subset and 611-pass full suite import and exercise every module) covers correctness but **not** lint-style hygiene — import order, unused names, formatting are unverified across the whole batch. This is Phase-4 Gap 3 and carries to the follow-up list. `pytest-textual-snapshot` was a recurring environment friction from batch-02; it was installed for this batch (the 27-baseline matrix runs), but its absence-by-default is the same pre-provisioning gap.

### 3.4 The increment-9 snapshot-baseline boundary call

Increment 9's functional rebuild of `PatchEditorPanel` deliberately changed the screen's layout, which made the `patch-comfortable-120x30` snapshot cell — the frozen image of the *inert* shell — go red. Regenerating that one baseline `.svg` would have touched a **6th file**, past the ≤5 cap. The increment correctly **stopped at the boundary and surfaced the call** rather than splitting silently (it is the snapshot analogue of the rewritten inert-shell unit tests). The single red cell was carried as a one-command pending item; by Phase 4 the full suite shows 27 snapshots passing, so the baseline was accepted within the increment-9→10 window. This is the workflow's stop-at-the-boundary discipline working as intended, but it is friction worth recording: a requirement-driven layout change inherently collides with a committed-artifact file cap.

---

## 4. Scope drift

**Net assessment: scope was held. Zero unapproved scope drift.** Scope stayed on change-list construction + CDFX I/O throughout; nothing in the deferred set (apply-to-image, export-modified-S19, undo/redo, XSD validation) was built. Three items warrant explicit examination because they look like drift but are not:

| Item | Increment | Assessment |
|---|---|---|
| The 9→11 increment re-plan | plan | **In scope — not drift.** The Phase-3 amendment (`Optional[int]` + LLR-004.9 + LLR-005.6) is an `architect` decision resolving a genuine requirements gap (§3.2); it added two LLRs (44 total) and two TCs (47 total) *to the requirements* and was folded into `01-requirements.md` before the re-plan. The two new increments (5, 6) implement amended/new LLRs — approved expansion, not feature creep. |
| Increment-9 +1-file CSS / snapshot overrun | 9 | **Examined — held at the boundary, not drift.** Increment 9 landed at exactly 5 files. The stale `patch-comfortable-120x30` snapshot baseline would have been a 6th file; the increment **did not touch it** — it stopped, surfaced the call for approval (increment-009 §5/§7), and deferred the one-command regeneration. The cap held; the boundary was respected. |
| The S8-2 fix folded into increment 10 | 10 | **In scope — not drift.** Increment 8's review packet §5 flagged that the 256 MB cap measured the *in-memory* byte length, so a path source was read fully before rejection (LLR-006.8 wants the *on-disk* size checked first). The S8-2 fix — a pre-read `stat().st_size` guard in `reader._resolve_source` — is corrective work directly necessary to satisfy LLR-006.8 as intended. It was disclosed in the increment-10 packet, counted against the 5-file cap, and folded into the standing increment-8 security review (no new I/O surface, no new dependency). Repairing a flagged hardening shortfall on an already-claimed LLR is in-scope, not new scope. |

Every increment delivered exactly its approved LLR set. No new runtime dependency was added — `pyproject.toml` / `requirements.txt` carry no batch-03 diff, the runtime set is `{rich, textual}` on both sides, the entire CDFX read/write is stdlib `xml.etree.ElementTree` + `xml.parsers.expat` (constraint C-2). The batch-02 inert-shell Patch Editor tests rewritten in increment 9 are a *requirement-driven* test change (LLR-007.1 supersedes the `R-TUI-027` deferral), disclosed and not a regression.

---

## 5. Metrics

### 5.1 Iterations per phase

| Phase | Iterations | Notes |
|---|---|---|
| 1 — Requirements | 3 | iter 1–2 drafting + OQ resolution; iter 3 closed all 28 Phase-2 findings (incl. the 3 blockers + the S-001 product decision) |
| 2 — Cross-agent review | 2 | iter 1 = parallel architect + qa + security review (28 findings); iter 2 = closure verification, all 28 closed, verdict `pass` |
| 3 — Implementation | 11 increments | Re-planned 9 → 11 by the Phase-3 array-coalescing amendment; ≤5-file cap held on all 11 |
| 4 — Validation | 1 | Single clean pass; verdict `pass-with-gaps`; no rollback forced |
| 5 — Post-mortem | 1 | This document |

### 5.2 Findings raised vs closed

| Source | Raised | Closed | Open at gate |
|---|---|---|---|
| Phase 2 iteration 1 | 28 (3 blockers · 10 majors · 15 minors) + 1 informational | 28 | 0 |
| Phase 2 iteration 2 (closure scan) | 4 new (CV-01..CV-04, all minor / informational) | folded into increment 1 / Phase 3 hand-off | 0 |
| Phase 3 — the array-coalescing amendment | 1 architect-level requirements gap (the `(name,index)` ambiguity) | resolved by the Phase-3 amendment (+2 LLR, +2 TC, 9→11 re-plan) | 0 |
| Phase 3 — S8-2 | 1 (increment-8 oversized-file hardening flag) | closed in increment 10 (pre-read `stat()` guard) | 0 |
| Security passes | 1 standing review on increment 8 (DOCTYPE rejection, write-path containment, `expat` hook ordering) — S8-2 folded into it | evidence captured in-packet | 0 |
| Phase 4 validation | 0 findings; 4 documentary/residual **gaps** recorded | carried to Phase 5/6 | 0 (none gate-blocking) |

**Finding closure ratio: 28/28 Phase-2 findings closed before Phase 3** (incl. all 3 blockers); CV-01..CV-04 dispositioned; the Phase-3 amendment and S8-2 both closed in-flight. **1 security pass** on increment 8, with the S8-2 hardening folded into it.

### 5.3 Test count growth

`419` (batch-02 baseline) **→ 611** (increment 11) — net **+192** on the batch path, **0 failed throughout**. Late-batch progression from the increment packets: 548 → **570** (inc 8, +22) → 590 (inc 9, +20, with the one expected snapshot-cell change) → **601** (inc 10, +10) → **611** (inc 11, +10 integration tests). The CDFX + Patch Editor subset is **192 passed / 0 failed** across 12 test files (179 `def test_*` functions, 192 collected after parametrization). 27 `pytest-textual-snapshot` baselines re-match. The 3 `xfail` rows and 2 skips are pre-existing batch-01/02 baseline cases, unchanged through all 11 increments — no batch-03 `xfail`.

### 5.4 Requirement coverage

| Dimension | Result |
|---|---|
| User stories | 7 |
| HLR | 8 / 8 `pass` · 0 partial · 0 fail |
| LLR | 44 / 44 `pass` · 0 partial · 0 fail (4+4+3+9+6+8+7+3 by HLR group) |
| TC | 47 / 47 `pass` (TC-001..TC-018, TC-019a..h, TC-020..026, TC-027a/b, TC-028..039) |
| Batch acceptance criteria | 11 / 11 met · 0 not-met |
| Engine freeze | zero bytes changed across `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` |
| New runtime dependency | none — runtime set unchanged at `{rich, textual}` |
| Open blocker findings at the Phase 4 gate | 0 |

Phase 4 verdict: **`pass-with-gaps`** — green suite, frozen engine, every requirement and AC satisfied; the `-with-gaps` qualifier records 4 documentary/residual gaps (no client `.cdfx` sample — RK-1; vCDM interop unverified — RK-2; `ruff` not run for increments 1–11; manual real-terminal Patch Editor pass not run in the headless environment). None is a correctness defect; none gates the batch.

---

## 6. Root-cause analysis — why the array-mapping gap escaped Phase 1 and Phase 2

The `(parameter_name, array_index)` ambiguity (§3.2) is the batch's most instructive defect and deserves a standalone read, because it escaped two review gates and surfaced only when the writer was built.

**Why it escaped Phase 1.** The change-list model was specified bottom-up from the *change-list's own needs*: an entry must name a parameter, optionally index into an array, and carry a value. `array_index: int` defaulting to `0` is a perfectly reasonable model **in isolation** — it expresses every change-list operation (add/edit/remove/dedup) correctly. The defect is not in the model; it is in the **interface between the model and the CDFX serialization format**. CDF 2.0 represents a scalar as a `VALUE` `SW-INSTANCE` with a bare `V` and an array as one `VAL_BLK` `SW-INSTANCE` with a `VG` — two structurally distinct shapes. The model needs a scalar-vs-array discriminator *because the writer needs one*; nothing in the change-list's own behaviour demands it. Phase 1 specified the model and the CDFX format as separate concerns and never cross-checked that the model could *drive* the format.

**Why it escaped Phase 2.** The Phase-2 review was thorough — 28 findings, including the closely-related A-09 (the `array_index` vs `SW-ARRAY-INDEX` naming-collision warning). But A-09 treated `array_index` as a *naming* hazard, not an *expressiveness* hazard: it said "don't serialize `array_index` as `SW-ARRAY-INDEX`", which is correct but orthogonal. No reviewer traced a worked example — a single-element array and a scalar of the same parameter — through the model and out the writer to discover that both produce the key `(name, 0)` and the writer has no way to tell them apart. The review checked each requirement for internal consistency and checked the reuse contracts; it did not execute the model against the format.

**What would have caught it earlier.** A **worked CDFX example exercised against the model in Phase 1** — taking the minimal CDF 2.0 shape from `design-input/cdfx-research.md` §3/§5 (one scalar `VALUE` instance + one `VAL_BLK` array instance) and walking it back through "what change-list entries must produce this?" — would have immediately shown that a scalar and an array element collide under an `int` index. This is the format-handler analogue of the discipline batch-02's post-mortem already prescribed (a *surface-enumeration pass before LLR drafting*) and batch-02 extended (*constraint-arithmetic*): when an LLR specifies a **model that must serialize to an external format**, Phase 1 must trace at least one concrete instance of that format *back through* the model and confirm the model can express every distinction the format draws. The change-list and the `.cdfx` were specified facing away from each other; one worked round-trip example on paper would have turned them to face each other.

**Cost of the miss.** It was not catastrophic — the dev-flow absorbed it cleanly: increment 4's review packet escalated it, the architect issued the Phase-3 amendment, and the 9→11 re-plan inserted two dedicated increments. But it reopened an already-shipped increment (1), rippled to two more files, added a model migration that the original plan had no slot for, and left a documented stale-test window (increment-4 writer tests built scalars with positional `array_index=0`, semantically stale after the migration until increment 6 rewrote them). The amendment is the workflow handling a real defect well; the lesson is that the defect should have been a Phase-1 finding, not a Phase-3 amendment.

---

## 7. Items proposed for the next batch

Consolidating the deferred scope, the owner-requested feature, and the Phase-4 gaps into candidate follow-up batches. Every item is derivable from an existing decision, gap, deferral, or owner request — no new requirements are invented.

### 7.1 Batch-04 — Raw MEMORY-value editing + unified change-set + selective export (owner-requested — prominent next batch)

**The owner has requested batch-04 directly.** Extend the Patch Editor so it can edit, alongside named A2L parameter changes, **raw MEMORY values** — direct `address → value` edits, not keyed to an A2L characteristic. The shape:

- A **unified change-set file** holding *both* kinds of change in one model: the existing parameter-name/array-index change-list **and** a new raw memory-field change-list (`address → value`, with byte width / endianness).
- **Selective export** from that unified change-set: the **parameter** changes export to CDFX (`.cdfx`, the existing writer — parameters are what CDF 2.0 represents); the **memory-field** changes export to a **separate file** (JSON or a similar simple format) since address→value edits have no natural CDFX representation.
- This is the bridge to the **deferred apply-to-image / export-modified-S19 work**: an `address → value` change-set is exactly the input an apply-to-image pass consumes, so batch-04 builds the data model that a future apply/export batch will act on (apply-to-image itself can be batch-05 or folded in if scope allows).

Architectural notes for batch-04 (to be confirmed in its Phase 1): the unified change-set should be a small superset model in the `cdfx/` package's spirit — a `changeset.py` peer to `changelist.py` — keeping the parameter and memory-field lists as separate typed collections rather than one polymorphic list, so the selective export is a clean per-collection dispatch. The memory-field export format is a one-way-door-ish choice (it becomes an interop contract); recommend a documented JSON schema, stdlib `json` only, no new dependency — consistent with C-2. Owner: `software-dev` after an `architect` Phase-1 design; `security-reviewer` loop-in for the new write path and any new load path. The CDFX writer/reader are reused unchanged for the parameter half.

### 7.2 Deferred-scope feature batches

**Batch — Apply-to-image / export-modified-S19.** The deferred core of the original Patch Editor vision: apply a change-set (parameter + memory-field) to the firmware memory map and export a modified S19 / Intel HEX. This **mutates firmware images** — a destructive surface — so it needs full `architect` + `qa` + `security` review. It depends on batch-04's unified change-set model as its input. The CLI already has `patch-hex`; this brings memory patching to the TUI. Likely the natural batch-05.

**Batch — Undo/redo history for the change-set.** The deferred undo/redo of edits. Smaller; can fold into batch-04 if its scope allows, or stand alone. Owner: `software-dev`.

### 7.3 Residual-risk and hygiene items (Phase-4 gaps)

- **RK-2 — a real vCDM round-trip check.** vCDM interop is asserted from Vector documentation, not verified against a live vCDM instance (no license/sample — A-5). The automated criterion achievable in-repo is "structurally valid CDF 2.0 per the `W-*`/`R-*` rule set"; true ASAM-XSD conformance is a deferred non-goal (C-3). **Recommendation:** a real vCDM round-trip stays a **client-side manual check** — produce a `.cdfx` with batch-03's writer, open it in a client vCDM installation, confirm it loads and the values match, and record the result. Flag this in the Phase-6 demo script / hand-off notes. Not closable inside a code batch.
- **RK-1 — no client `.cdfx` sample.** Producer-specific variation (namespaces, `ADMIN-DATA`, `SW-CS-HISTORY`) is mitigated by tolerant reading (LLR-005.3/TC-017) but unverified against real output. **Recommendation:** if a public CDF 2.0 sample under a redistributable licence can be obtained (research §9 cites MathWorks Vehicle Network Toolbox docs), add it as one optional supplementary fixture. Optional, not a blocker; C-9 forbids bundling a *client* sample regardless.
- **`ruff` in CI.** `ruff check .` / `ruff format --check .` was never run for increments 1–11. Add it to `.github/workflows/tui-ci.yml` so lint hygiene is verified going forward. No code change anticipated; if `ruff` flags real issues, fix them in that pass. This pairs naturally with batch-04's Phase-3 environment setup — pre-provision the toolchain as increment 1's first action.
- **Manual real-terminal Patch Editor pass (Gap 4).** A ~10-minute manual eyeball pass before merge — `s19tui --load examples/case_00_public/prg.s19`, open the Patch Editor (rail item 6), add/edit/remove, save and load a `.cdfx`, observe the `W-INSTANCE-EXCLUDED` / `W-ARRAY-SPARSE` / `W-WRITE-CONTAINMENT` status lines. The integration TCs (TC-025/026/036/027a) cover the behaviour; the residual is subjective real-terminal aesthetics. A pre-merge action for Javier, not a batch.
- **CV-01** — the §6.3 OQ-3 "containment" vs "resolution" wording is a one-line editorial item with no natural touch-point; fold into the Phase-6 docs sweep.

### 7.4 Suggested execution order

Phase 6 docs sweep for batch-03 (closes CV-01, refreshes `REQUIREMENTS.md` `R-*` traceability, `docs/diagrams/`) → **batch-04** (owner-requested unified change-set + memory-value editing; pre-provision `ruff` here) → apply-to-image / export-modified-S19 (batch-05, depends on batch-04). RK-1/RK-2 are client-side and run in parallel, outside the dev-flow batches.

---

## 8. Process learnings for the GRNDIA dev-flow

1. **A model that must serialize to an external format must be Phase-1-tested *against* that format.** The array-mapping gap (§3.2/§6) escaped two gates because the change-list model and the CDFX format were specified as separate concerns and never cross-checked. Batch-01 prescribed a surface-enumeration pass; batch-02 extended it to constraint-arithmetic; batch-03 extends it again: **when an LLR specifies a model that must round-trip through an external format, Phase 1 must trace at least one concrete worked example of that format back through the model and confirm the model can express every distinction the format draws.** Add to the Phase-1 checklist: *"for every model that serializes to an external format, one worked round-trip example is walked through the model in the requirements doc."*

2. **A first-pass blocker count is a signal, not a failure.** Phase 2 raised 3 blockers and forced a rollback — but all three were closable specification edits (a wrong arithmetic count, a non-executable fixture, a missing safety LLR), caught *before* a line of those features was written. Contrast batch-02, whose A-03 contradiction also surfaced in Phase 2. The pattern holds: the cross-agent review is doing its job precisely when it forces a rollback on a spec defect, because a spec defect caught in Phase 2 is an order of magnitude cheaper than the same defect caught in Phase 3 (which is exactly what the array-mapping gap cost).

3. **A re-plan mid-Phase-3 is acceptable when an amendment is genuine — but it must be a numbered, provenance-kept artifact.** The 9→11 re-plan was handled well: the amendment was folded into `01-requirements.md` first, the superseded 9-increment plan was kept verbatim for provenance, the reopened shipped files were enumerated, and the stale-test window was disclosed in two increment packets so Phase 4 would not misread it. This is the template for any future mid-implementation amendment: amend the requirements first, keep the old plan, enumerate the blast radius, disclose every stale artifact.

4. **Pre-provision the dev toolchain before Phase 3.** `ruff` was missing for all 11 increments — the second consecutive batch with this exact gap (batch-02 had it for 11 of 12 increments). `py_compile` is a correctness substitute, not a lint check. Phase-3 increment 1 must verify and install the full declared dev toolchain as its first action. This is now a repeated finding and should be a hard Phase-3 entry gate, not a recommendation.

5. **The package-boundary discipline carries forward and works.** Placing the data-processing layer in a Textual-free `cdfx/` package made increments 5–8 fully unit-testable with the app running unchanged, made C-8 verifiable by inspection, and kept the engine freeze achievable. The `tui/services/` seam pattern (mirroring `a2l_service`) was the right reuse. The dev-flow's increment-isolation and review-packet discipline localized every defect to its increment; the friction in batch-03 was in *requirement authoring* (the array-mapping gap), not in the workflow.

6. **A `pass-with-gaps` Phase-4 verdict is the right resolution for residual risk.** The four Phase-4 gaps are documentary (manual pass), environmental (`ruff`), or genuine accepted residual risk (no client `.cdfx`, no live vCDM). The `-with-gaps` qualifier records them honestly without forcing a rollback or an extra iteration. RK-2 (vCDM) in particular is a residual risk that *cannot* be closed inside any code batch — naming it as accepted-residual rather than as a defect is the verdict working as intended.

---

## 9. Decision (user gate)

Per the dev-flow Phase 5 spec, three options:

1. **`close-batch`** *(architect recommends)* — the functional Patch Editor + CDFX deliverable is complete and independently validated: 611-test green suite, zero-diff engine freeze, no new runtime dependency, 8 HLR / 44 LLR / 47 TC all `pass`, 11/11 acceptance criteria met, all 28 Phase-2 findings closed. Advance to Phase 6 (docs) — update `REQUIREMENTS.md` `R-*` traceability for the new `cdfx/` package and the functional Patch Editor screen, refresh `docs/diagrams/`, produce the batch functionality summary and a demo script (HLR-003/HLR-007 `demo` corroboration), close CV-01 — then `/dev-flow-sync-en` to upload to the Obsidian vault. The deferred scope and the owner-requested batch-04 are queued as well-scoped follow-up batches per §7.

2. **`open-new-batch`** — start batch-04 (the owner-requested memory-value editing) immediately, skipping batch-03's Phase 6. **Not recommended** — Phase 6 wraps the CDFX feature into client-facing traceability/docs; skipping it leaves the `R-*` map stale as the seed for batch-04's requirements, and batch-04 builds directly on the `cdfx/` package whose docs Phase 6 produces.

3. **`iterate`** — reopen Phase 3 to fold a gap item inline. **Not recommended** — none of the 4 gaps is a correctness defect; `ruff`-in-CI and the manual pass are quick pre-merge actions, RK-1/RK-2 are client-side and uncloseable in-repo, and `iterate` is meant for blocker-level rework, of which there is none.

**Recommendation: option 1 — `close-batch`.** The batch met every requirement and acceptance criterion with independently verified evidence; the array-mapping gap was a real defect but was absorbed and resolved cleanly within Phase 3. The remaining work — most prominently the owner-requested batch-04 (unified change-set + raw MEMORY-value editing + selective export) — is genuinely separate scope that belongs in fresh, well-scoped batches, not in a re-opened batch-03.

---

*Phase 5 post-mortem of batch-03 (functional Patch Editor + ASAM CDFX). Synthesizes the architecture/process perspective with the QA/quality/metrics evidence from `04-validation.md` (Phase 4, authored by the `qa-reviewer`). Authored by the `architect` agent — 2026-05-21.*
