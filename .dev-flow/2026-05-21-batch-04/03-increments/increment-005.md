# Increment 005 — Review Packet — s19_app batch-04

**Phase:** 3 — Implementation
**Increment:** 5 of 9 — Unified change-set file write
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-005.1, LLR-005.2, LLR-005.3, LLR-005.4
**TCs covered:** TC-015, TC-016, TC-017, TC-018
**Date:** 2026-05-21

---

## 1. What changed

Added the **write half** of the unified change-set JSON file handler. The new
module `s19_app/tui/cdfx/unified_io.py` serializes a `UnifiedChangeSet`
(increment 4) into a single JSON document and writes that document into the
work area through the existing, already-hardened `workspace.copy_into_workarea`
containment primitive. `serialize_unified(changeset) -> bytes` builds the JSON
document — a `format` identifier, a `version`, a `parameters` half (one plain
JSON object per `ChangeListEntry` carrying `parameter_name` / `array_index` /
`value` / `status`, **not** CDFX XML — LLR-005.2) and a `memory` half (a JSON
**array of objects**, each with `address` as an integer-valued field — never a
JSON object key — and `new_bytes` as an integer array, per LLR-005.3 / DD-10).
`write_unified_to_workarea(...)` mirrors `writer.write_cdfx_to_workarea`
exactly: it stages the serialized bytes to a transient file inside
`.s19tool/workarea/temp/`, then calls `copy_into_workarea` to perform the
containment-checked final placement — no new write path is introduced
(constraint C-10). A containment / reparse-point rejection is caught and
surfaced as one `MF-WRITE-CONTAINMENT` warning `ValidationIssue`
(collect-don't-abort), never an uncaught exception. The nine `MF-*` rule codes
are defined here as named constants (this module is their pinned home for the
increment-6 reader). Stdlib `json` only — no new dependency.

The new symbols are re-exported from `cdfx/__init__.py`; `conftest.py` gains a
`make_unified_file` helper (a real well-formed unified file on disk, built via
the production serializer — needed by the increment-6 read TCs); and
`tests/test_unified_write.py` covers TC-015..TC-018, including the
path-containment / reparse-point arm via both an injectable `copy_fn` seam (runs
on every OS) and a real symlink with a recorded-reason `skipif`.

---

## 2. Files modified

| # | File | Change | Purpose |
|---|------|--------|---------|
| 1 | `s19_app/tui/cdfx/unified_io.py` | **New** | `serialize_unified` + `write_unified_to_workarea` (write half); the `MF-*` rule-code constants, format-id / version tokens; `_encode_parameter_entry` / `_encode_memory_entry` / `_safe_name` / `_containment_issue` helpers. |
| 2 | `s19_app/tui/cdfx/__init__.py` | **Edit** | Re-export `serialize_unified` + `write_unified_to_workarea`; package docstring notes the new `unified_io` module. |
| 3 | `tests/conftest.py` | **Edit** | Add `make_unified_file` — writes a well-formed unified JSON file via the production `serialize_unified` (consumed by the increment-6 read / round-trip tests). |
| 4 | `tests/test_unified_write.py` | **New** | TC-015..TC-018 — 18 tests: JSON structure, parameter-half encoding, memory-half array-of-objects shape, work-area containment incl. the deterministic + real reparse-point arms and the dedup-suffix arm. |
| 5 | `.dev-flow/2026-05-21-batch-04/03-increments/increment-005.md` | **New** | This review packet. |

File count: **5 / 5** — within the cap. `workspace.py`, the engine, and the
existing `cdfx/` modules (`changelist.py`, `changeset.py`, `memory.py`,
`writer.py`, `reader.py`, …) were **not** modified.

---

## 3. How to test

```powershell
# new test file only
python -m pytest -q tests/test_unified_write.py

# full suite (baseline 674 + 18 new = 692)
python -m pytest -q

# import surface
python -c "import s19_app.tui.cdfx; print(sorted(s19_app.tui.cdfx.__all__))"

# compile gate (ruff not installed — py_compile substitute)
python -m py_compile s19_app/tui/cdfx/unified_io.py s19_app/tui/cdfx/__init__.py tests/conftest.py tests/test_unified_write.py

# write-then-reload shape check
python -c "import json, tempfile; from pathlib import Path; from tests.conftest import unified_changeset_factory; from s19_app.tui.cdfx import write_unified_to_workarea; d=tempfile.mkdtemp(); p,i=write_unified_to_workarea(unified_changeset_factory(), Path(d), 'x.json'); doc=json.loads(p.read_bytes()); print(sorted(doc), doc['memory'][0])"
```

---

## 4. Test results (actual output)

**`pytest -q tests/test_unified_write.py`** — all 18 pass:

```
..................                                                       [100%]
18 passed in 0.15s
```

The real-reparse-point arm (`test_tc018_real_reparse_point_traversal_rejected`)
**ran** on this machine — the OS / account has symlink-create privilege; it was
not skipped. On a CI image without the privilege it carries a recorded-reason
`skipif` so the skip is visible in the report.

**`pytest -q`** (full suite):

```
27 snapshots passed.
692 passed, 2 skipped, 3 xfailed in 182.65s (0:03:02)
```

Baseline was 674 passed / 2 skipped / 3 xfailed / 0 failed. Increment 5 adds the
18 `test_unified_write.py` cases → **692 passed / 2 skipped / 3 xfailed / 0
failed**. The 2 skips and 3 xfails are the unchanged baseline ones.

**`py_compile`** — `PY_COMPILE_OK` (all four files compile clean; `ruff` is not
installed, `py_compile` is the substitute per the task brief).

**Import surface** — `IMPORT_OK`, `__all__` now includes `serialize_unified` and
`write_unified_to_workarea` alongside the existing symbols.

**Write-then-reload shape check** — actual output:

```
top-level keys : ['format', 'memory', 'parameters', 'version']
format/version : s19app-unified-changeset 1.0
param entries  : 8
memory entries : 3
memory[0]      : {'address': 512, 'new_bytes': [222, 173, 190, 239], 'status': 'unvalidated-no-image'}
addr is int    : True
resolved path  : True
```

A unified file written by `write_unified_to_workarea` re-loads with `json.load`
to the LLR-005.1/.3 shape: `format` + `version` header, `parameters` and
`memory` halves, the memory half an array of objects with `address` as a Python
`int`, and the file resolving under `.s19tool/workarea/`.

---

## 5. Risks

- **`copy_fn` default resolution.** `write_unified_to_workarea` takes
  `copy_fn: CopyIntoWorkarea | None = None` and resolves `None` to the
  module-level `copy_into_workarea` *at call time* (not as a captured default
  argument). This was a deliberate fix after the first test run: a captured
  default would make `monkeypatch.setattr(unified_io, "copy_into_workarea", …)`
  a no-op. Both seams are now meaningful and both are tested
  (`test_tc018_containment_rejection_surfaces_issue_not_exception` for the
  explicit `copy_fn` arg, `test_tc018_containment_rejection_via_monkeypatched_helper`
  for the module-symbol monkeypatch). Low residual risk — a future caller that
  forgets to leave `copy_fn=None` would bypass the reused helper, but that is
  exactly what the monkeypatch test guards against.
- **`status` field persisted in both halves.** `serialize_unified` writes the
  `ResolutionStatus` / `MemoryStatus` token into each entry. Per A-7 and the
  TC-025 equality predicate the status is *re-derived on read*, so the
  persisted value is informational only. The increment-6 reader must **not**
  trust it. Flagged for increment 6 — not a defect here.
- **Memory-half wire shape is invisible until round-trip.** A wrong shape
  (`address` as an object key) would not surface until TC-025. Mitigated:
  `test_tc017_address_is_an_integer_field_never_an_object_key` asserts the raw
  JSON text directly (`"address": 512` present, `"512":` absent), so the shape
  is pinned now, not at increment 9.
- **No size bound on the *write* path.** `write_unified_to_workarea` does not
  cap the produced document size. This is in line with the spec — the size cap
  (LLR-006.4) and decoded-structure ceiling (LLR-006.5) are *read*-path
  concerns (increment 6). A pathologically large in-memory `UnifiedChangeSet`
  is an upstream/UI concern, not this increment's.

---

## 6. Pending items

- **Read half (increment 6).** `read_unified` + the full `MF-*` rule set
  enforcement (`MF-JSON-PARSE` incl. the `RecursionError` catch,
  `MF-BAD-STRUCTURE`, `MF-NO-ADDRESS`, `MF-EMPTY-BYTES`, `MF-BYTE-RANGE`,
  `MF-VERSION-UNKNOWN`, `MF-SIZE-CAP`, `MF-ENTRY-LIMIT`, `MF-PATH-UNRESOLVED`).
  The `MF-*` constants are defined in `unified_io.py` ready for it; only
  `MF-WRITE-CONTAINMENT` is *emitted* by this increment.
- **`make_unified_file` is introduced but not yet consumed.** It is added here
  (the writer produces the file) for the increment-6 `read_unified` /
  round-trip TCs; no increment-5 test uses it. Intentional per the plan §C
  increment-5 file list.
- **Security-reviewer hand-off.** Per the plan §D and the cross-functional
  rule, increments 5–7 carry the write-path containment and read-path resource
  bounds. Increment 5's `write_unified_to_workarea` should get a
  `security-reviewer` pass (it reuses the hardened `copy_into_workarea` and
  re-inlines no containment logic — the review surface is small).

---

## 7. Suggested next task

**Increment 6 — Unified change-set file read + `MF-*` rule set.** Add the read
half to `unified_io.py`: `read_unified(path_text, base_dir, size_probe=...) ->
tuple[UnifiedChangeSet, list[ValidationIssue]]` — `resolve_input_path` →
256 MB size cap → `json.load` (catching `JSONDecodeError` **and**
`RecursionError`) → `MF-BAD-STRUCTURE` shape check before any half indexing →
per-entry `MF-*` rules → decoded-structure ceiling. Re-export `read_unified`,
add the malformed / rule-violation / oversized / deeply-nested / over-ceiling
conftest fixtures, and add `tests/test_unified_read.py` + `test_unified_rules.py`
(TC-014, TC-019..TC-024, TC-035, TC-037). The `make_unified_file` helper and the
`MF-*` constants from this increment are the read half's inputs.
