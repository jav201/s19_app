# Post-mortem — s19_app — 2026-05-21-batch-04

**Phase:** 5 — Post-mortem
**Iteration:** 1
**Date:** 2026-05-22
**Batch:** batch-04 — memory-value editing + unified change-set + selective export
**Branch:** `dev-flow/batch-02-direction-b-restyle` @ `701a849` (shared working tree — batch-02 + batch-03 + batch-04 accumulating uncommitted; owner to split/commit at a logical point)
**Source artifacts:** `state.json` (`decisions_log`), `01-requirements.md`, `02-review.md` (Phase 2 iteration 1 + iteration-2 closure), `03-increments/increment-plan.md` + `increment-001.md` … `increment-009.md`, `04-validation.md`
**Author:** `architect` agent — synthesizing the architecture/process perspective with the QA/quality/metrics evidence from `04-validation.md` (Phase 4, authored by the `qa-reviewer`)

---

## 0. Executive summary

Batch-04 extended the Patch Editor from an A2L-parameter-only tool into a **two-change-kind** tool: alongside the batch-03 parameter `ChangeList` it now edits **raw memory values** — entries keyed by a memory `address`, each carrying a contiguous run of new bytes. The two kinds are held behind one in-app **unified change-set** container and one on-disk JSON file, and a **selective export** splits them back into the two artifacts each consumer expects — a `.cdfx` for the parameter half (via the byte-unchanged batch-03 CDFX writer) and a separate JSON file for the memory-field half. Like batch-03, this **deliberately added a data layer** — six new pure-Python modules inside `s19_app/tui/cdfx/` — while keeping the parsing/validation engine byte-frozen. Scope was held to the memory-change model + unified file I/O + selective export; applying changes to the firmware image, exporting a modified S19/HEX, and undo/redo were all out of scope by design.

The batch ran the full V-model dev-flow in 5 phases. Phase 4 closed with a clean gate:

- pytest suite **631 → 762 passing** (net +131 across the batch path), **0 failed, 3 xfailed, 2 skipped, 27 snapshots passed** — reproduced in Phase 4 with zero drift.
- The engine-freeze `git diff main` over `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` is **empty — zero bytes changed**; the batch-04 feature is purely additive new files.
- The batch-03 CDFX writer/resolver (`writer.py`, `resolve.py`) are confirmed **byte-unchanged** by a SHA-256 pin; `changelist.py` / `reader.py` carry no batch-04 edit.
- All **37 TC / 9 HLR / 37 LLR** verdict `pass`; all **10 §5.9 acceptance criteria** met.
- Phase 2 raised **22 findings (1 blocker)** — all 22 closed before Phase 3; one security pass over increments 5–7; the security finding S57-02 closed in increment 9.

| Phase | Iterations | Artifact | Key result |
|---|---|---|---|
| 1 — Requirements | 2 | `01-requirements.md` | 5 US, 9 HLR, 37 LLR, 37 TC; iter 2 closed all Phase-2 findings |
| 2 — Cross-agent review | 2 | `02-review.md` | iter 1: 1 blocker / 7 majors / 14 minors / 1 info; iter 2: all 22 closed, `pass` |
| 3 — Implementation | 9 increments | `increment-plan.md` + `increment-001.md`…`009.md` | +131 tests, engine zero-diff, batch-03 CDFX byte-unchanged, no re-plan |
| 4 — Validation | 1 | `04-validation.md` | verdict `pass-with-gaps`; 0 blockers; 4 documentary/environmental gaps |
| 5 — Post-mortem | 1 | this document | recommend **close-batch**; queue apply-to-image + follow-ups |

**Recommendation: `close-batch`.** The deliverable is complete and independently validated; the deferred scope (apply-to-image / export-modified-S19, undo/redo) and the four documentary/environmental gaps are well-scoped follow-up work — not reasons to keep batch-04 open. The single most notable process result is that batch-04 **caught its cross-component reuse gap (A-1) in Phase 2 review — before implementation** — exactly where batch-03 caught its analogous gap only in Phase 3; the batch-03 root-cause learning was applied (see §6).

---

## 1. Batch summary

### Objective

Per `state.json`: *"Extend the Patch Editor to edit raw MEMORY values (memory address → value/bytes), not only A2L parameters. A unified change-set file holds BOTH the A2L parameter change-list (batch-03) and the memory-field changes. Selective export from the unified file: a CDFX for the parameter half (reusing the batch-03 CDFX writer) + a separate JSON file for the memory-field half. SCOPE: memory-change model + unified change-set file read/write + selective export. NOT in scope: applying changes to the firmware image / exporting modified S19 (remains deferred)."* Batch-03 had made the Patch Editor functional for A2L parameter changes; batch-04 adds the second, parallel change kind and unifies both behind one container and one file.

### What shipped

- **The batch-04 memory layer inside `s19_app/tui/cdfx/`** — six new pure-Python modules, no Textual import, peer to the batch-03 `changelist.py` / `writer.py` / `reader.py`:
  - `memory.py` — the memory-change model: `MemoryChange` (fields `address`, `new_bytes` stored as an immutable `tuple[int, ...]`, validation `status`; `__post_init__` raises `ValueError` on a malformed byte run; an `addressed_range` property), `MemoryChangeList` with add/edit/remove, `address` entry identity (re-add updates in place), deterministic insertion order, and `MemoryStatus`.
  - `memory_validate.py` — `validate_memory_changes`: stamps each entry `inside` / `partial` / `outside` / `unvalidated-no-image` against the loaded image's `LoadedFile.ranges`, runs the inter-entry overlap check, and collects one warning `ValidationIssue` per partial/outside/overlap finding — collect-don't-abort, address-and-byte-count-only messages (no raw `new_bytes` in the log).
  - `memory_display.py` — `format_memory_value` / `MemoryValueRendering`: hex-primary (uppercase two-digit space-separated), an ASCII companion with the pinned `.` (`0x2E`) placeholder, and a decimal companion — derived for display only, never mutating the stored bytes.
  - `changeset.py` — `UnifiedChangeSet`: holds one batch-03 `ChangeList` + one `MemoryChangeList` by **composition**, exposes each half independently, reports per-half counts and an empty-state query.
  - `unified_io.py` — the unified-file JSON writer + reader + the `MF-*` rule set: `serialize_unified` / `write_unified_to_workarea` (staged-temp-then-`copy_into_workarea` containment) and `read_unified` (path resolution → 256 MB size cap → `json.load` catching `JSONDecodeError` **and** `RecursionError` → structural shape check → per-entry rules → decoded-structure ceiling). Nine `MF-*` codes plus the write-path `MF-WRITE-CONTAINMENT`.
  - `export.py` — `export_unified`: the selective-export coordinator — re-resolves the parameter half against the loaded A2L, calls the **unchanged** `write_cdfx_to_workarea`, writes the memory-field JSON, and combines per-half-tagged issues.
- **`cdfx/__init__.py`** — extended with the new public re-export surface (no batch-03 logic touched) and a docstring note that the package now also holds the memory-field / unified-change-set concern.
- **`tui/services/cdfx_service.py`** — extended (not replaced): `CdfxService` migrated from owning a bare `ChangeList` to owning a `UnifiedChangeSet`, with `change_list` kept as a backward-compatible property alias so every batch-03 caller still works; new memory-change, save/load-unified and selective-export operations.
- **The Patch Editor UI extension** — `PatchEditorPanel` gained a second `DataTable` for memory changes, address / new-bytes inputs, memory add/edit/remove buttons and a unified save/load/export control row; `app.py` got UI-state wiring only (action routing through `CdfxService`).

### What did not ship (deferred by design — scope held)

Applying the memory changes / parameter changes to the firmware image or memory map; exporting a modified S19 / Intel HEX firmware file; undo/redo of edits in either change kind; editing/creating memory regions outside the loaded image's ranges (out-of-range edits are *flagged* but recorded, never applied); any change to the batch-03 CDFX format, writer, reader, or the parameter `ChangeList` semantics. These carry to follow-up batches — see §7.

---

## 2. What worked

### 2.1 The layered increment arc — model → validate → display → container → write → read → export → UI → round-trip (architecture)

The 9-increment sequence followed a strict dependency order, mirroring batch-03's discipline: memory-change model (inc 1) → range validation (inc 2) → value display (inc 3) → unified container (inc 4) → unified-file write (inc 5) → unified-file read + `MF-*` rule set (inc 6) → selective-export coordinator (inc 7) → Patch Editor UI extension (inc 8) → round-trip + inspection hardening + the S57-02 fix (inc 9). Each increment consumed only what earlier increments delivered, each left a runnable `s19tui` and a green suite, and the single increment that mutated running UI behaviour (inc 8) was correctly isolated and second-to-last. Unlike batch-03 — which needed a mid-Phase-3 9→11 re-plan when the array-mapping gap surfaced in the writer increment — **batch-04 ran its planned 9 increments end to end with no re-plan**: the dependency-ordered arc held because the cross-component seam (the A-1 CDFX-writer reuse defect) had already been resolved in Phase 1, so increment 7's export coordinator had a callable contract to implement.

### 2.2 Reusing the batch-03 `cdfx/` package and `write_cdfx_to_workarea` literally unchanged (architecture)

Batch-04's highest-leverage architectural decision was to **extend the existing `s19_app/tui/cdfx/` package rather than open a new sibling** — `01-requirements.md` §2.1 and the increment plan §A both made this explicit: the memory-change model is a TUI-side edit-intent artifact, it belongs beside the parameter `ChangeList` that already lives in `cdfx/`, and adding a peer there keeps one import surface and one `cdfx_service` orchestration layer. The reuse went further: the selective export feeds the parameter half through the **byte-unchanged** batch-03 `write_cdfx_to_workarea` (constraint C-1), and the staged-temp-then-`copy_into_workarea` write pattern was reused verbatim for the two new write paths (constraint C-10 — no new write path). Phase 4 confirmed this held at the strictest level: `test_cdfx_unchanged.py` SHA-256-pins `writer.py` and `resolve.py` byte-unchanged, and the worktree diff over every batch-03 CDFX module is empty. The package-boundary discipline carried forward from batch-02/03 and worked again — the six new modules are fully unit-testable in isolation, and the `app.py`-clean claim (C-7) was true by construction and verified by the TC-027 inspection.

### 2.3 The security review catching the decoded-structure / RecursionError / write-path gaps in Phase 2 — before implementation (architecture + security)

The Phase-2 security-reviewer pass produced three majors that were each a real attack surface left unbounded by the requirements as drafted, and **all three were closed by requirements edits before a line of those modules was written**:

- **S-001** caught that the 256 MB size cap bounds the *on-disk file*, not the *decoded in-memory structure* — a sub-cap well-formed file can declare hundreds of millions of `new_bytes` integers. The fix added LLR-006.5: a documented entry-count ceiling and single-`new_bytes`-run-length ceiling, enforced during reader reconstruction, emitting an `MF-ENTRY-LIMIT` issue, collect-don't-abort.
- **S-002** caught that `RecursionError` from deeply-nested JSON is a `RuntimeError`, **not** a `json.JSONDecodeError`, so it escapes a `JSONDecodeError`-only `except` clause and crashes the load. The fix amended LLR-006.2 to require the reader catch `RecursionError`.
- **S-003** caught that LLR-007.2 specified the memory-field file *content* with no write-path safety clause — the exact shape of the batch-03 S-001 blocker, reproduced for one of the three files this batch writes. The fix added a containment clause mirroring LLR-005.4.

This is a sharp contrast with batch-03, where the analogous cross-component gap (the array-mapping defect) escaped both Phase 1 and Phase 2 and surfaced only in Phase 3 increment 4. Here the security pass found the unbounded read-path surface in the requirements text — and the increment plan then carried the fixes into increments 5–7 with a dedicated security hand-off.

### 2.4 The engine verified untouched at zero diff; the batch-03 CDFX writer byte-unchanged (architecture + QA)

Although batch-04 added a real data layer, the parsing/validation engine was held frozen. The Phase-4 `git diff main` over `core.py`, `hexfile.py`, `range_index.py`, the entire `validation/` directory, `tui/a2l.py` and `tui/mac.py` returned **empty output — zero bytes changed**. The `ValidationIssue` model needed no edit — every batch-04 finding passes the existing model an `artifact` string tag (`memory-half` / `param-half`) on the model's existing free-form `artifact: str` field (constraint C-5), exactly as batch-03 did with `artifact="cdfx"`. The batch-03 CDFX writer and resolver are pinned byte-unchanged by SHA-256; the whole batch-04 feature is six new untracked modules plus additive edits to `cdfx/__init__.py`, `cdfx_service.py`, `conftest.py` and `app.py`. The no-regression criterion holds at the strictest possible level.

### 2.5 Suite 631 → 762 with zero regressions (QA)

The suite grew from the batch-04 631-pass baseline to **762 passing** across the batch path, **0 failed throughout**. The batch-04 memory/unified/export subset alone (11 test files, 145 `def test_*` functions, 151 collected after parametrization) is **151 passed / 0 failed**; the `-m snapshot` subset re-matches all 27 committed baselines. Every one of the 37 LLR maps to ≥1 passing TC; all 10 §5.9 acceptance criteria are met — including the round-trip gate (TC-025, exact float `==` on three adversarial IEEE binary64 values — `0.1`, the `5e-324` denormal, a 17-significant-digit value — with no tolerance), the rule-code-completeness gate (all nine `MF-*` codes provoked), and the containment/resource-bound gate (TC-018/021/022/035/037). TC-025 is genuinely non-tautological: the denormal and the 17-significant-digit fixture fail under any lossy intermediate string conversion.

> **Baseline-number note.** The batch-04 Phase-3 increment plan §0 records a **611-pass** entering baseline (the batch-03 increment-11 number). The increment-8 packet records its entering baseline as **733** and the increment-9 packet records **749 → 762**. The post-mortem and Phase 4 both take **631** as the batch-04 starting point and **762** as the close — the net **+131** is measured across the batch-04 increment path as executed; the 611-vs-631 discrepancy in the plan header is a stale-number carry-over from the batch-03 plan template, not a test regression, and is flagged for the Phase 6 docs sweep.

---

## 3. What didn't / friction

### 3.1 The Phase-2 A-1 blocker — the CDFX writer's mandatory `ResolutionResult` argument was unmodelled

Phase-2 iteration 1 surfaced **1 blocker — A-1** — and the dev-flow forced a rollback to a Phase-1 iteration 2. The defect: LLR-007.1 told the export coordinator to call the **unchanged** batch-03 writer `write_cdfx_to_workarea(...)`, but that writer's signature takes a **mandatory `resolution: ResolutionResult` positional argument** — a typed object carrying the parameter entries resolved against the loaded A2L. The unified change-set (per A-7 / LLR-004.1 / LLR-005.2) deliberately models the parameter half as a **plain `ChangeList`** with no `ResolutionResult` attached, and the unified file format is deliberately resolution-free. So as worded, the central reuse contract of the whole batch — "reuse the batch-03 CDFX writer unchanged" — was **not callable**: an implementer following the requirement literally would hit a `TypeError` at the export call.

A-1 was a specification defect, not an implementation impossibility, and its resolution was **already chosen in the review** (option (a)): the export coordinator re-resolves the parameter `ChangeList` against the currently loaded A2L immediately before calling the writer — via the batch-03 `resolve_against_a2l` path, mirroring how `cdfx_service` resolves before a CDFX write — and feeds the writer a freshly-built `ResolutionResult`. The writer stays literally unchanged (C-1 honored); the unified file stays resolution-free. The iteration-2 edit amended LLR-007.1, added the new **LLR-007.5** (export-time re-resolution), and widened LLR-004.1 / A-7. No product-owner decision was pending, so iteration 2 was a single focused editorial pass. **The crucial point — see §6 — is that A-1 is the structural analogue of batch-03's array-mapping gap, but it was caught in Phase 2, not Phase 3.** The cost was one Phase-1 iteration plus a Phase-2 closure pass — an order of magnitude cheaper than the increment-reopening, two-extra-increment re-plan that batch-03's equivalent gap cost.

### 3.2 The transient Anthropic API incident delayed the batch-04 start (~12 min)

The `state.json` Phase-0 `decisions_log` entry records that *"a transient Anthropic API incident delayed the start ~12 min."* This is an environmental friction, not a workflow or requirements defect — it cost wall-clock time at the batch boundary and produced no rework. It is recorded here for completeness and because the batch ran in autonomous mode (the operator was away), where an unrecovered API incident could have stalled the whole run; in this case it self-resolved and the batch proceeded normally.

### 3.3 `ruff` still not installed — the third consecutive batch

`ruff` was absent from the Phase-3/Phase-4 environment for **all 9 increments**; each increment substituted `python -m py_compile` on every changed Python file and recorded `ruff` as a pending item. This is the **third batch in a row** with this exact gap — batch-02 had it for 11 of 12 increments, batch-03 for all 11. The mitigation (every module compiles; the 151-pass batch-04 subset and 762-pass full suite import and exercise every module) covers correctness but **not** lint-style hygiene — import order, unused names, formatting are unverified across the whole batch. This is Phase-4 Gap 2 and carries to the follow-up list. Batch-03's post-mortem already recommended making toolchain pre-provisioning a hard Phase-3 entry gate; that recommendation was **not actioned** before batch-04, which is itself a process finding (see §8).

---

## 4. Scope drift

**Net assessment: scope was held. Zero unapproved scope drift.** Scope stayed on the memory-change model + unified file I/O + selective export throughout; nothing in the deferred set (apply-to-image, export-modified-S19, undo/redo, creating new memory ranges) was built. Two items warrant explicit examination because they look like drift but are not:

| Item | Increment | Assessment |
|---|---|---|
| Increment-8 +1-file `styles.tcss` + snapshot regen | 8 | **Examined — within plan allowance, not drift.** Increment 8 landed at exactly 5 files (`cdfx_service.py`, `screens_directionb.py`, `app.py`, `styles.tcss`, the new test file). The increment plan §C/§D **explicitly anticipated** `styles.tcss` as the kind of 4th/5th-file inclusion the new Patch Editor widget ids require, and explicitly allowed including it and flagging it — which the increment-8 packet §5 did. The regenerated `patch-comfortable-120x30` snapshot `.svg` is **not new logic** — it is the mechanical re-snapshot of a layout change (the Patch Editor screen genuinely grew a second `DataTable`), regenerated for that one cell only with `--snapshot-update`, exactly as batch-03's increment 9 did. The cap held; the boundary call was surfaced for review, not taken silently. |
| The S57-02 fix folded into increment 9 | 9 | **In scope — not drift.** The increment 5–7 security hand-off / Phase-3 security pass flagged S57-02: `write_unified_to_workarea` and `write_memory_field_to_workarea` caught only `WorkareaContainmentError`, so an `OSError` from the staged-temp write (full disk, denied permission) would escape uncaught and break the LLR-005.4 / LLR-007.2 "never an uncaught exception" collect-don't-abort claim. The S57-02 fix — an `except OSError` arm converting the fault to one `MF-WRITE-CONTAINMENT` issue — is corrective work directly necessary to satisfy two already-claimed LLRs as intended. It was disclosed in the increment-9 packet, the two source edits + two new test files stayed within the 5-file cap, and the increment-9 packet also flagged the residual `MF-WRITE-CONTAINMENT`-reused-for-`OSError` semantic-breadth note. Repairing a flagged hardening shortfall on an already-claimed LLR is in-scope, not new scope — the same disposition batch-03's post-mortem gave its S8-2 fix. |

Every increment delivered exactly its approved LLR set. No new runtime dependency was added — `requirements.txt` carries zero diff, `pyproject.toml` carries no batch-04 diff (the only diff is the pre-existing batch-02 restyle), the runtime set is `{rich, textual}` on both sides, and every file read/write this batch performs uses stdlib `json` only (constraint C-4). The `CdfxService` ownership migration (`ChangeList` → `UnifiedChangeSet`) is a requirement-driven change kept fully backward-compatible by a property alias — disclosed, not a regression.

---

## 5. Metrics

### 5.1 Iterations per phase

| Phase | Iterations | Notes |
|---|---|---|
| 1 — Requirements | 2 | iter 1 = drafting + OQ resolution by best-criteria defaults (operator away); iter 2 = closed all 22 Phase-2 findings incl. the A-1 blocker |
| 2 — Cross-agent review | 2 | iter 1 = parallel architect + qa + security review (22 findings); iter 2 = closure verification, all 22 closed, verdict `pass` |
| 3 — Implementation | 9 increments | Planned 9, executed 9 — **no re-plan**; ≤5-file cap held on all 9 |
| 4 — Validation | 1 | Single clean pass; verdict `pass-with-gaps`; no rollback forced |
| 5 — Post-mortem | 1 | This document |

### 5.2 Findings raised vs closed

| Source | Raised | Closed | Open at gate |
|---|---|---|---|
| Phase 2 iteration 1 | 22 (1 blocker · 7 majors · 14 minors) + 1 informational (S-007, no-action) | 22 | 0 |
| Phase 2 iteration 2 (closure scan) | 2 new (CV-01, CV-02 — minor / editorial) | folded into Phase 3 increment 1 | 0 |
| Phase 3 — security pass on increments 5–7 | 1 (S57-02 — `OSError` escapes the containment catch) | closed in increment 9 (`except OSError` arm) | 0 |
| Phase 4 validation | 0 findings; 4 documentary/environmental **gaps** recorded | carried to Phase 5/6 | 0 (none gate-blocking) |

**Finding closure ratio: 22/22 Phase-2 findings closed before Phase 3** (including the 1 blocker). CV-01/CV-02 folded into increment 1. **1 security pass** over increments 5–7, with **S57-02 raised and closed in-flight** (increment 9). No finding was open at any phase gate.

### 5.3 Test count growth

`631` (batch-04 entering baseline) **→ 762** (increment 9) — net **+131** on the batch path, **0 failed throughout**. Late-batch progression from the increment packets: 733 (entering inc 8) → **749** (inc 8, +16 — the TC-032/033/034 integration tests) → **762** (inc 9, +13 — 9 TC-025 round-trip + 2 TC-027 inspection + 2 S57-02). The batch-04 memory/unified/export subset is **151 passed / 0 failed** across 11 test files (145 `def test_*` functions, 151 collected after parametrization). 27 `pytest-textual-snapshot` baselines re-match — batch-04 added no new snapshot baseline (it is a data-layer + screen-wiring batch; the Patch Editor memory behaviour is verified by `App.run_test()` integration tests, not SVG baselines). The 3 `xfail` rows and 2 skips are pre-existing batch-01/02/03 baseline cases, unchanged through all 9 batch-04 increments — no batch-04 `xfail`, no unexpected `xpass`.

### 5.4 Requirement coverage

| Dimension | Result |
|---|---|
| User stories | 5 |
| HLR | 9 / 9 `pass` · 0 partial · 0 fail |
| LLR | 37 / 37 `pass` · 0 partial · 0 fail (4+5+3+5+4+5+5+3+3 by HLR group) |
| TC | 37 / 37 `pass` (TC-001 … TC-037; no reserved/unallocated slot) |
| Batch acceptance criteria | 10 / 10 met · 0 not-met |
| Engine freeze | zero bytes changed across `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` |
| Batch-03 CDFX modules | `writer.py` / `resolve.py` byte-unchanged (SHA-256 pin); `changelist.py` / `reader.py` no batch-04 edit |
| New runtime dependency | none — runtime set unchanged at `{rich, textual}` |
| Open blocker findings at the Phase 4 gate | 0 |

Phase 4 verdict: **`pass-with-gaps`** — green suite, frozen engine, byte-unchanged batch-03 CDFX writer, every requirement and AC satisfied; the `-with-gaps` qualifier records 4 documentary/environmental gaps (no live vCDM round-trip — RK-2; `ruff` not run for increments 1–9; manual real-terminal Patch Editor pass not run in the headless environment; the `MF-WRITE-CONTAINMENT`-reused-for-`OSError` semantic-breadth note). None is a correctness defect; none gates the batch.

---

## 6. Root-cause analysis — why batch-04 caught its cross-component gap in Phase 2, where batch-03 caught its analogue only in Phase 3

This is the most instructive comparison the batch offers, and it deserves a standalone read because it tests directly whether the **batch-03 root-cause learning was applied**.

**The two gaps are structurally the same defect.** Batch-03's array-mapping gap: the change-list model and the CDFX serialization format were specified as separate concerns and never cross-checked, so the model (`array_index: int` defaulting to `0`) could not express a distinction the format draws (scalar `VALUE` vs `VAL_BLK` array) — the model could not *drive* the writer. Batch-04's A-1 blocker: the unified change-set's parameter half (a plain `ChangeList`, deliberately resolution-free) and the batch-03 CDFX writer's call contract (a mandatory `ResolutionResult` argument) were specified facing away from each other — the model could not *be passed to* the writer. Both are **interface-between-a-model-and-a-format-handler** defects; both make a load-bearing reuse contract uncallable as worded.

**Batch-03's gap escaped two gates and surfaced in Phase 3.** No Phase-1 or Phase-2 reviewer traced a worked example across the model↔format seam; increment 4's writer build was the first time anyone executed the model against the format, and it cost a requirements amendment, a reopened increment, and a 9→11 re-plan. Batch-03's post-mortem §6 distilled the lesson into a process learning: *"when an LLR specifies a model that must round-trip through an external format, Phase 1 must trace at least one concrete worked example of that format back through the model and confirm the model can express every distinction the format draws."*

**Batch-04's gap was caught in Phase 2 review — and that is the learning applied.** A-1 is exactly the failure the batch-03 learning predicts, and the Phase-2 architect review found it by doing exactly what the learning prescribes: it traced the export call path — *coordinator holds a bare `ChangeList`* → *calls `write_cdfx_to_workarea`* → *writer requires a `ResolutionResult`* — across the component boundary, against the actual batch-03 writer signature, and found the seam did not connect. The finding text is explicit that this is a "callability defect" checked against the real signature, not a style nit. Notably the requirements document **already carried the seam awareness** that batch-03 lacked: assumption A-7 was written to say the parameter half is "re-resolved against the loaded A2L at selective-export time" — the drafting team had thought about the seam. A-1 was the *gap between that stated intent and the LLR that operationalized it* (LLR-007.1 still said "call the writer unchanged" without the re-resolution step). So the learning was applied at two levels: the requirements drafting anticipated the seam in the assumptions, and the Phase-2 review caught the one LLR where the operational detail had not caught up — before any code was written.

**Why batch-04 still needed a Phase-2 catch rather than a Phase-1 catch.** The ideal — per the batch-03 learning — is that the worked example is walked *in the Phase-1 requirements doc itself*. Batch-04 got most of the way there (A-7 names the re-resolution) but the Phase-1 draft did not fully reconcile A-7 with LLR-007.1, so it took the Phase-2 review to close the last gap. This is a partial, not complete, application of the learning: the seam was *named* in Phase 1 but not *traced to a callable contract* in Phase 1. The residual improvement for future batches: when an assumption (like A-7) names a cross-component transformation, every LLR that touches that seam must be checked against the assumption *in the same Phase-1 pass* — not left for Phase 2 to reconcile.

**Cost comparison — the learning paid off.** Batch-03's gap: a Phase-3 amendment, a reopened shipped increment, two inserted increments, a 9→11 re-plan, a documented stale-test window. Batch-04's gap: one Phase-1 iteration-2 editorial pass (amend one LLR, add one LLR, widen one assumption), no code reopened, no re-plan, the planned 9 increments executed as planned. The cross-agent review forcing a Phase-2 rollback on a spec defect is the workflow working as intended — and batch-04 is the evidence that catching the seam defect a phase earlier is materially cheaper.

---

## 7. Items proposed for the next batch

Consolidating the still-deferred scope, the standing batch-02/03 follow-ups, and the Phase-4 gaps into candidate follow-up batches. Every item is derivable from an existing decision, gap, deferral, or prior post-mortem — no new requirements are invented.

### 7.1 The long-deferred core — Apply-to-image / export-modified-S19

The deferred core of the original Patch Editor vision, and now the most natural next batch: **apply the change-set to the firmware memory map and export a modified S19 / Intel HEX**. Batch-04 built exactly the data model this consumes — the `UnifiedChangeSet`, with the memory half already an `address → new_bytes` shape that an apply-to-image pass reads directly, and the parameter half resolvable to concrete addresses via the existing resolution path. This batch **mutates firmware images** — a destructive surface — so it needs full `architect` + `qa` + `security` review and a `security-reviewer` loop-in is mandatory (the CLI already has `patch-hex`; this brings memory patching to the TUI). It depends on batch-04's unified change-set as its input; it is the natural batch-05.

### 7.2 Undo/redo for the change-set

The deferred undo/redo of edits in either change kind, explicitly out of scope for both batch-03 and batch-04. Smaller than apply-to-image; can stand alone or fold into the apply-to-image batch if its scope allows. Owner: `software-dev` after a short `architect` design note (an undo stack over the `UnifiedChangeSet` mutations is a reversible, well-bounded design).

### 7.3 Standing follow-up batches carried from batch-02's post-mortem

Batch-02's post-mortem queued a set of feature batches that remain open and are not touched by batch-03 or batch-04:

- **CRC engine** — checksum verification/computation over firmware ranges.
- **Bookmarks** — saved address markers in the hex view.
- **PDF export** — exporting an inspection report.
- **Polish batch** — accumulated UI/UX refinements.

These are independent of the change-set work and can be scheduled around the apply-to-image batch by operator priority.

### 7.4 Residual-risk and hygiene items (Phase-4 gaps)

- **RK-2 — a real vCDM round-trip check.** vCDM (Vector Calibration Data Management) is the target consumer of the `.cdfx` produced by the selective-export parameter half. Batch-04 does not change the CDFX format — it reuses the byte-unchanged batch-03 writer — so this is exactly the batch-03 position: compatibility is asserted from Vector documentation, not tested against a live vCDM instance (no licence, no sample). **Recommendation:** a real vCDM round-trip stays a **client-side manual check** — produce a `.cdfx`, open it in a client vCDM installation, confirm it loads and the values match. Flag it in the Phase-6 demo script / hand-off notes. Not closable inside a code batch.
- **`ruff` in CI.** `ruff check .` / `ruff format --check .` was never run for increments 1–9 — the **third consecutive batch** with this gap. Add it to `.github/workflows/tui-ci.yml` so lint hygiene is verified going forward; no code change is anticipated, and if `ruff` flags real issues, fix them in that pass. This must be paired with pre-provisioning the toolchain as the **first action of the next batch's Phase 3 increment 1** — see §8.
- **Manual real-terminal Patch Editor pass (Gap 3).** A ~10-minute manual eyeball pass before merge — `s19tui --load examples/case_00_public/prg.s19`, open the Patch Editor, add/edit/remove a memory change, observe the hex/ASCII/decimal rendering and the `inside`/`partial`/`outside` status, save and load a unified `.json`, trigger the selective export. The integration TCs (TC-032/033/034) cover the behaviour; the residual is subjective real-terminal aesthetics. A pre-merge action for Javier, not a batch.
- **`MF-WRITE-IO` code (Gap 4).** The increment-9 S57-02 fix reuses `MF-WRITE-CONTAINMENT` for a plain `OSError` — slightly broad (a full disk is an I/O fault, not a containment-traversal fault). The behaviour is correct and tested; a dedicated `MF-WRITE-IO` code is an optional one-line follow-up for a future batch, not a defect to fix now.
- **TC-028 / TC-030 test-name label swap.** The two `test_tc028_*` / `test_tc030_*` test names are swapped relative to the §5.7 catalogue titles; both behaviours are fully covered and green, traceability is intact. A cosmetic rename for the Phase-6 docs sweep, not a finding.
- **The 611-vs-631 plan-header baseline number** (see §2.5 note) — a stale carry-over from the batch-03 plan template; correct it in the Phase-6 docs sweep.

### 7.5 Suggested execution order

Phase 6 docs sweep for batch-04 (refresh `REQUIREMENTS.md` `R-*` traceability for the new memory layer, refresh `docs/diagrams/`, produce the batch functionality summary + demo script for the HLR-003/HLR-009 `demo` corroboration, fix the TC-028/030 names and the plan-header number) → **pre-provision `ruff`** and add it to CI → **apply-to-image / export-modified-S19** (batch-05, depends on batch-04's unified change-set) → undo/redo and the batch-02 standing batches by operator priority. RK-2 (live vCDM) is client-side and runs in parallel, outside the dev-flow batches.

---

## 8. Process learnings for the GRNDIA dev-flow

1. **The "trace a worked example across the component boundary" learning works — apply it one phase earlier still.** Batch-03's post-mortem prescribed tracing a model↔format example before LLR drafting; batch-04's A-1 blocker is exactly that class of defect and it was caught in Phase 2 review by tracing the export call path against the real `write_cdfx_to_workarea` signature — a phase earlier than batch-03's equivalent, at a fraction of the cost (§6). The residual: the requirements draft *named* the cross-component re-resolution in assumption A-7 but left one LLR (LLR-007.1) unreconciled with it. **Add to the Phase-1 checklist:** *"for every assumption that names a cross-component transformation, every LLR touching that seam is checked against the assumption in the same Phase-1 pass — the seam is traced to a callable contract, not just named."*

2. **A single-blocker Phase-2 result with a pre-chosen resolution is the cheapest possible rollback.** Batch-03 took 3 blockers and a 3-iteration Phase 1; batch-04 took 1 blocker, its resolution was fixed in the review itself (no product decision pending), and Phase 1 iteration 2 was a single editorial pass. The pattern: the cross-agent review is most valuable when it not only finds the defect but also lands the resolution, so the rollback iteration is mechanical. This is the workflow at its most efficient — and worth holding as the target shape for a Phase-2 rollback.

3. **A planned increment count that survives Phase 3 unchanged is a signal the Phase-1/2 seam work was sufficient.** Batch-03 needed a 9→11 re-plan because a cross-component gap surfaced mid-implementation; batch-04 ran its planned 9 increments end to end. The absence of a re-plan is not luck — it is the downstream payoff of closing the A-1 seam defect in Phase 2. A mid-Phase-3 re-plan should be read as a retroactive signal that a seam was under-specified; its absence, as confirmation the requirements were build-ready.

4. **Pre-provision the dev toolchain before Phase 3 — this is now a three-batch repeated finding and must become a hard gate.** `ruff` was missing for all 9 batch-04 increments, after being missing for batch-02 (11/12) and batch-03 (all 11). Batch-03's post-mortem already recommended making toolchain provisioning a hard Phase-3 entry gate; the recommendation was not actioned, and batch-04 reproduced the gap. **A recommendation that is not actioned and recurs is a process failure of the post-mortem loop itself.** The next batch's Phase-3 increment 1 must verify-and-install the full declared dev toolchain as its literal first action, and the dev-flow Phase-3 entry checklist should block on it — not recommend it.

5. **The package-boundary discipline carries forward across three batches and keeps paying off.** Extending the Textual-free `cdfx/` package rather than opening a new sibling kept the six new modules unit-testable in isolation, made the `app.py`-clean constraint (C-7) true by construction, and kept the engine freeze and the batch-03-CDFX-byte-unchanged guarantees achievable. The `tui/services/` seam (the `CdfxService` extension with a backward-compatible property alias for the `ChangeList`→`UnifiedChangeSet` migration) absorbed a model-ownership change with zero batch-03 caller breakage. The dev-flow's increment-isolation and review-packet discipline localized every defect to its increment; batch-04's only friction was a single Phase-2 spec catch and an environmental API blip — neither in the workflow itself.

6. **A `pass-with-gaps` Phase-4 verdict remains the right resolution for residual risk.** The four Phase-4 gaps are environmental (`ruff`), documentary (manual pass, the `MF-WRITE-IO` note) or genuine accepted residual risk (no live vCDM). The `-with-gaps` qualifier records them honestly without forcing a rollback or an extra iteration. RK-2 in particular cannot be closed inside any code batch — naming it accepted-residual rather than a defect is the verdict working as intended, consistent with batch-03.

---

## 9. Decision (user gate)

Per the dev-flow Phase 5 spec, three options:

1. **`close-batch`** *(architect recommends)* — the memory-value editing + unified change-set + selective-export deliverable is complete and independently validated: 762-test green suite (net +131, 0 failed), zero-diff engine freeze, byte-unchanged batch-03 CDFX writer, no new runtime dependency, 9 HLR / 37 LLR / 37 TC all `pass`, 10/10 acceptance criteria met, all 22 Phase-2 findings closed (incl. the A-1 blocker), the S57-02 security finding closed in-flight. Advance to Phase 6 (docs) — update `REQUIREMENTS.md` `R-*` traceability for the new memory layer, refresh `docs/diagrams/`, produce the batch functionality summary and a demo script (HLR-003/HLR-009 `demo` corroboration), fix the TC-028/030 test-name swap and the stale plan-header baseline number — then `/dev-flow-sync-en` to upload to the Obsidian vault. The deferred scope and the standing follow-ups are queued as well-scoped follow-up batches per §7.

2. **`open-new-batch`** — start the apply-to-image / export-modified-S19 batch immediately, skipping batch-04's Phase 6. **Not recommended** — Phase 6 wraps the unified-change-set feature into client-facing traceability/docs; the apply-to-image batch builds directly on the `UnifiedChangeSet` whose docs Phase 6 produces, so skipping it leaves the `R-*` map stale as the seed for the next batch's requirements.

3. **`iterate`** — reopen Phase 3 to fold a gap item inline. **Not recommended** — none of the 4 gaps is a correctness defect; `ruff`-in-CI and the manual pass are quick pre-merge actions, RK-2 is client-side and uncloseable in-repo, the `MF-WRITE-IO` code is an optional future one-liner, and `iterate` is meant for blocker-level rework, of which there is none.

**Recommendation: option 1 — `close-batch`.** The batch met every requirement and acceptance criterion with independently verified evidence; the one Phase-2 blocker was a spec defect caught and resolved before implementation — and notably caught a full phase earlier than batch-03's structural analogue, evidence that the batch-03 root-cause learning was applied. The remaining work — most prominently the long-deferred apply-to-image / export-modified-S19 batch — is genuinely separate scope that belongs in fresh, well-scoped batches, not in a re-opened batch-04.

---

*Phase 5 post-mortem of batch-04 (memory-value editing + unified change-set + selective export). Synthesizes the architecture/process perspective with the QA/quality/metrics evidence from `04-validation.md` (Phase 4, authored by the `qa-reviewer`). Authored by the `architect` agent — 2026-05-22.*
