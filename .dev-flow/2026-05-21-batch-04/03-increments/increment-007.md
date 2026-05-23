# Increment 007 — Selective export coordinator — Review Packet

**Batch:** 2026-05-21-batch-04 — memory-field change kind + unified change-set + selective export
**Phase:** 3 — Implementation
**Increment:** 7 of 9 — `export.py` (`export_unified`) — the selective-export coordinator
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs:** LLR-007.1..LLR-007.5 · **TCs:** TC-028, TC-029, TC-030, TC-031, TC-036

---

## 1. What changed

Added the **selective-export coordinator** — `s19_app/tui/cdfx/export.py` — the
hand-off step that splits a `UnifiedChangeSet` back into the two artifacts each
downstream consumer expects. `export_unified(unified_change_set, loaded_a2l,
base_dir, ...)` (a) **re-resolves** the parameter-half `ChangeList` against the
loaded A2L through the **unchanged** batch-03 `resolve_against_a2l` to obtain a
transient `ResolutionResult`, then invokes the **unchanged** batch-03
`write_cdfx_to_workarea(change_list, resolution, ...)` to produce the CDFX file;
(b) writes the memory-field half as a separate JSON file via a new
`write_memory_field_to_workarea` helper that reuses the same
serialize-to-temp-then-`copy_into_workarea` containment path as the increment-5
unified-file writer; (c) collects each half's `ValidationIssue`s into one
combined result and tags the **per-half origin** on the existing
`ValidationIssue.artifact` field (`param-half` / `memory-half`). With **no A2L**
loaded the coordinator mirrors the batch-03 `unresolved-no-a2l`
collect-don't-abort pattern: it still runs the resolver (every entry →
`UNRESOLVED_NO_A2L`), collects one informational `MF-EXPORT-NO-A2L` issue, and
proceeds without raising. The batch-03 CDFX writer (`writer.py`) and resolver
(`resolve.py`) are **byte-unchanged** — called, never edited (constraint C-1).
The result is a typed `ExportResult` dataclass. All four new public symbols are
re-exported from `cdfx/__init__.py`.

## 2. Files modified

| # | File | Change | Purpose |
|---|------|--------|---------|
| 1 | `s19_app/tui/cdfx/export.py` | **New** | `export_unified` coordinator, `ExportResult`, `serialize_memory_field`, `write_memory_field_to_workarea`; per-half artifact tags (`PARAM_HALF_ARTIFACT`/`MEMORY_HALF_ARTIFACT`), `EXPORT_NO_A2L` code. Re-resolve → unchanged CDFX writer → memory-field JSON write → tag+combine issues. |
| 2 | `s19_app/tui/cdfx/__init__.py` | **Edit** | Re-export `export_unified` / `ExportResult` / `serialize_memory_field` / `write_memory_field_to_workarea`; package docstring updated to record the `export` module. |
| 3 | `tests/test_unified_export.py` | **New** | TC-028..031 + TC-036 — 16 tests, A2L-loaded and no-A2L arms. |

**File count: 3 of 5** — within cap. `tests/conftest.py` was **not** touched:
the increment plan's step 4 ("confirm `make_patch_a2l` importable; add a fixture
if needed") proved unnecessary — `make_patch_a2l` lives locally in
`test_cdfx_resolve.py` (not conftest), so the export test builds its own
self-contained synthetic A2L (`_EXPORT_A2L_TEXT`) covering the four parameter
names of `change_list_factory`. `unified_changeset_factory` (conftest, already
present) supplies the change-set. `unified_io.py` was **not** edited — the
`write_memory_field_to_workarea` helper is cleanest in `export.py` (it reuses
`unified_io._encode_memory_entry` and the public `CopyIntoWorkarea` type), so
the plan's optional "edit `unified_io.py`" path was not taken.

**Byte-unchanged (verified):** `cdfx/writer.py`, `cdfx/resolve.py`,
`cdfx/changelist.py`, `cdfx/reader.py`, `workspace.py`, `validation/model.py`,
the engine/parsers. The CDFX writer is hash-pinned by TC-030.

## 3. How to test

```
# from repo root C:\Users\jjgh8\Github\s19_app
python -m pytest -q tests/test_unified_export.py        # the new TC-028..031, TC-036
python -m pytest -q                                     # full suite — baseline + new
python -c "import s19_app.tui.cdfx"                      # package import
python -m py_compile s19_app/tui/cdfx/export.py s19_app/tui/cdfx/__init__.py tests/test_unified_export.py
```

Functional export check (build a `UnifiedChangeSet`, export with + without an
A2L, confirm a `.cdfx` and a memory `.json` land in the work area) — run inline
during this increment; output captured in §4.

`ruff` is not installed in this environment — `python -m py_compile` was
substituted per the increment instructions.

## 4. Test results (actual output)

**New test file** — `pytest -q tests/test_unified_export.py`:
```
................                                                         [100%]
16 passed in 0.20s
```

**Full suite** — `pytest -q`:
```
27 snapshots passed.
733 passed, 2 skipped, 3 xfailed in 182.64s (0:03:02)
```
Baseline was **717 passed / 2 skipped / 3 xfailed / 0 failed**; now **733 passed**
(717 + 16 new) / 2 skipped / 3 xfailed / **0 failed**. No regressions.

**Import / compile:**
```
py_compile: OK
import s19_app.tui.cdfx: OK
s19tui app import: OK
```

**Functional export check** (inline, captured):
- *No-A2L arm:* `export_unified(cs, None, base)` →
  `cdfx=patchset.cdfx`, `memjson=memory-field.json`, both files exist under
  `.s19tool/workarea/`; issues `[('MF-EXPORT-NO-A2L','param-half','info'),
  ('W-INSTANCE-EXCLUDED','param-half','warning'),
  ('W-EMPTY-CHANGELIST','param-half','warning')]`; memory JSON carries
  `format`/`version`/`memory`, `address` as integer field, exact byte runs.
- *A2L-loaded arm:* `export_unified(cs, tags, base)` → both files produced,
  `issues=[]`, the resolved `IGN_ADVANCE_BASE` appears in the exported CDFX
  text, no `MF-EXPORT-NO-A2L` issue.

**TC mapping:**
- **TC-028** (LLR-007.1) — CDFX file produced under work area; spy confirms the
  call routes through the unchanged `write_cdfx_to_workarea` fed the
  change-set's own `ChangeList` + a `ResolutionResult`. ✅
- **TC-029** (LLR-007.2) — memory-field `.json` produced under work area; valid
  JSON, format-id/version header, LLR-005.3 array-of-objects shape (`address`
  an integer field, never a key), byte-deterministic. ✅
- **TC-030** (LLR-007.3 / C-1) — two distinct files, never merged; `writer.py`
  source SHA-256 hash-pinned and asserted byte-unchanged. ✅
- **TC-031** (LLR-007.4) — every combined-result issue tagged `param-half` /
  `memory-half` (never the raw `cdfx`/`unified` tag); a memory-half containment
  rejection still produces the CDFX file (collect-don't-abort across halves). ✅
- **TC-036** (LLR-007.5) — A2L-loaded arm: spy confirms `resolve_against_a2l`
  re-resolution, and that its `ResolutionResult` object is the one fed to the
  CDFX writer; no-A2L arm: export proceeds, one info `MF-EXPORT-NO-A2L` issue,
  every parameter entry `UNRESOLVED_NO_A2L`, no raise; empty `[]` tag list
  treated as no-A2L. ✅

## 5. Risks

- **A-1 blocker resolution.** The coordinator re-resolves the bare `ChangeList`
  *before* the CDFX write (DD-11 / LLR-007.5), exactly mirroring
  `cdfx_service.save`. Getting this wrong would reproduce the original
  `TypeError`-at-export defect. TC-036 spies the resolver call and asserts its
  `ResolutionResult` is the object fed to the writer — the regression is pinned.
- **`writer.py` byte-unchanged guard.** TC-030 hashes `writer.py` content
  (SHA-256 `82d527c0…fe4ac`). If a *deliberate* future change touches the
  writer, `_WRITER_PY_SHA256` in `test_unified_export.py` must be updated
  intentionally — the test fails loud and tells you the new hash. The hash is
  over file *content*, robust to `__pycache__` noise. (Note: it is **not**
  robust to a pure line-ending change — if the repo's git autocrlf setting
  rewrites line endings on checkout the hash would shift; on this Windows
  checkout the file is LF-stored and the hash is stable. Flagged for the
  increment-9 TC-027 inspection, which the plan also assigns a byte-unchanged
  check — the two should use the same mechanism.)
- **Stale test assumption fixed mid-increment.** The first TC-031 draft assumed
  a complete-A2L export yields `W-*` issues; with the full synthetic A2L the
  export is clean (zero issues — correct behavior). The "every issue tagged"
  test was moved to the no-A2L arm (guaranteed to produce issues); the *tagging*
  assertion is unchanged. No scope creep — caught and corrected.
- **`copy_fn` seam scope.** `export_unified`'s `copy_fn` parameter redirects
  only the **memory-field** write; the CDFX write always goes through the
  unchanged `write_cdfx_to_workarea` (which has no such seam — C-1). A test
  needing to force a *CDFX*-side containment rejection must monkeypatch
  `export.write_cdfx_to_workarea` instead. Documented in the `export_unified`
  docstring.
- **`resolve_fn` injection seam.** Added purely so TC-036 can spy the
  re-resolution; defaults to the real `resolve_against_a2l`. Production callers
  (increment 8 service) leave it at the default — it is not a behavior knob.

## 6. Pending items

- None within increment-7 scope. `unified_io.py` and `conftest.py` were
  intentionally not edited (see §2) — the plan listed both as conditional.
- **Security-reviewer pass over increments 5–7** is scheduled next per the
  plan's §D security hand-off — this increment carries the memory-field export
  write-path containment (a new write *target*, but the **reused**
  `copy_into_workarea` primitive — no new write path, C-10).

## 7. Suggested next task

**Increment 8 — Patch Editor UI extension** (LLR-009.1..LLR-009.3): extend
`CdfxService` with memory-change operations + unified `save_unified` /
`load_unified` / `export_selective` (wrapping `changeset.py`, `unified_io.py`,
`export.py`), extend `PatchEditorPanel` with memory-change rows/controls and
save/load/export actions, wire the action messages in `app.py` (UI-state only).
This is the tightest increment (4 files, all edits to large existing modules) —
flag at the boundary if the layout genuinely needs a 6th file rather than
exceeding the cap. After it ships, propose the TC-032/033/034 manual test plan
to `qa-reviewer`.

---

*Increment boundary reached — stopping here. Increment 8 not started.*
