# Increment 006 — Review Packet — s19_app batch-04

**Phase:** 3 — Implementation
**Increment:** 6 of 9 — Unified change-set file read + `MF-*` rule set
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-006.1, LLR-006.2, LLR-006.3, LLR-006.4, LLR-006.5,
LLR-008.1, LLR-008.2
**TCs covered:** TC-014, TC-019, TC-020, TC-021, TC-022, TC-023, TC-024,
TC-035, TC-037
**Date:** 2026-05-22

---

## 1. What changed

Added the **read half** of the unified change-set JSON file handler. The new
function `read_unified(path_text, base_dir, size_probe=None) -> tuple[UnifiedChangeSet, list[ValidationIssue]]`
in `s19_app/tui/cdfx/unified_io.py` is the on-disk-to-in-app side of the unified
change-set: it loads a unified-file JSON document and reconstructs a
`UnifiedChangeSet` (increment 4), collecting every structural and per-entry
fault as a `ValidationIssue` and **never raising** on a data-quality fault
(collect-don't-abort, A-4).

The read path is a fixed pipeline. (1) **Path resolution** — the user-supplied
path is resolved through the existing `workspace.resolve_input_path` (cwd +
repo-root walk + `exists()`); an unresolvable path is one `MF-PATH-UNRESOLVED`
issue and **no file is opened** (LLR-006.3). (2) **Pre-parse size cap** — the
on-disk byte size is probed through an injectable `size_probe` seam; a size
over the 256 MB `READ_SIZE_CAP_BYTES` (the shared
`workspace.DEFAULT_COPY_SIZE_CAP_BYTES`) is one `MF-SIZE-CAP` issue and
`json.load` is **never reached** (LLR-006.4). (3) **Parse** — `json.load` with
the `except` clause catching `json.JSONDecodeError` **and** `RecursionError`
(plus `UnicodeDecodeError`) → one `MF-JSON-PARSE` issue; `RecursionError` is a
`RuntimeError`, not a `JSONDecodeError`, and a deeply-nested document overflows
the stdlib parser's C recursion, so a bare `except json.JSONDecodeError` would
let it escape and crash the load (LLR-006.2 / S-002). (4) **Structural shape
guard** — `_is_unified_shape` checks the decoded document is a dict carrying
both halves **before** indexing either one; a well-formed-but-wrong-shape
document (a bare `[]`, `42`, a string, an object with no halves) is one
`MF-BAD-STRUCTURE` issue, never an uncaught `KeyError` (LLR-006.2 / Q-07).
(5) **Version check** — an unrecognised `version` token is one info-level
`MF-VERSION-UNKNOWN` issue and parsing continues (LLR-008.2). (6) **Per-half
reconstruction** — `_decode_parameter_half` / `_decode_memory_half` /
`_decode_memory_entry` apply the per-entry `MF-*` rule set
(`MF-NO-ADDRESS` / `MF-EMPTY-BYTES` / `MF-BYTE-RANGE`, LLR-008.1) and the
decoded-structure ceiling (`MF-ENTRY-LIMIT`, LLR-006.5) — each fault drops the
offending entry and keeps the rest.

The two **decoded-structure ceilings** of LLR-006.5 are pinned as documented
named constants in `unified_io.py`: `MF_ENTRY_COUNT_CEILING = 100_000`
(memory-field entry count — a realistic patch set is tens-to-hundreds of
entries, 100k is generous headroom) and `MF_RUN_LENGTH_CEILING = 1_048_576`
(1 MiB single-`new_bytes`-run length — a genuine raw-memory edit is
tens-to-thousands of bytes, 1 MiB is generous headroom). They are read by the
`make_over_ceiling_unified_file` fixture so fixture and reader can never
disagree. The `MF-*` code spellings were already pinned as constants in the
increment-5 write half; the read half emits them. Every issue message
references an address / a count, never the raw `new_bytes` content
(constraint C-9).

`read_unified` is re-exported from `cdfx/__init__.py`; `conftest.py` gains the
four read fixtures (`make_malformed_unified_file`,
`make_rule_violation_unified_file`, `make_deeply_nested_unified_file`,
`make_over_ceiling_unified_file`); and `tests/test_unified_read.py` (TC-014,
TC-019, TC-021, TC-022, TC-035, TC-037) + `tests/test_unified_rules.py`
(TC-020, TC-023, TC-024) cover the increment — 25 new tests. Stdlib `json`
only — no new dependency.

---

## 2. Files modified

| # | File | Change | Purpose |
|---|------|--------|---------|
| 1 | `s19_app/tui/cdfx/unified_io.py` | **Edit** (add read half) | `read_unified` + `_is_unified_shape` / `_decode_parameter_half` / `_coerce_resolution_status` / `_decode_memory_half` / `_decode_memory_entry` / `_read_issue`; the `READ_SIZE_CAP_BYTES` / `MF_ENTRY_COUNT_CEILING` / `MF_RUN_LENGTH_CEILING` constants and the `SizeProbe` seam type; module docstring extended. |
| 2 | `s19_app/tui/cdfx/__init__.py` | **Edit** | Re-export `read_unified`; package + module docstring note the reader is now present. |
| 3 | `tests/conftest.py` | **Edit** | Add `make_malformed_unified_file`, `make_rule_violation_unified_file`, `make_deeply_nested_unified_file`, `make_over_ceiling_unified_file` — the four adversarial read fixtures. |
| 4 | `tests/test_unified_read.py` | **New** | TC-014, TC-019, TC-021, TC-022, TC-035, TC-037 — 16 tests: parse-both-halves, wrong-shape/no-`KeyError`, path resolution / no-open spy, size cap / no-`json.load` spy, deeply-nested / no-`RecursionError`, the two decoded-structure ceilings. |
| 5 | `tests/test_unified_rules.py` | **New** | TC-020, TC-023, TC-024 — 9 tests: malformed JSON, the three per-entry structural rules, the version rule. |

File count: **5 / 5** — within the cap. `workspace.py`, the engine, and the
existing `cdfx/` modules (`changelist.py`, `changeset.py`, `memory.py`,
`memory_validate.py`, `memory_display.py`, `writer.py`, `reader.py`) were
**not** modified. The increment-5 write half of `unified_io.py` is byte-unchanged
except for the docstring and import edits.

---

## 3. How to test

```powershell
# the two new test files only
python -m pytest -q tests/test_unified_read.py tests/test_unified_rules.py

# full suite (baseline 692 + 25 new = 717)
python -m pytest -q

# import surface
python -c "import s19_app.tui.cdfx; print('read_unified' in s19_app.tui.cdfx.__all__)"

# compile gate (ruff not installed — py_compile substitute)
python -m py_compile s19_app/tui/cdfx/unified_io.py s19_app/tui/cdfx/__init__.py tests/conftest.py tests/test_unified_read.py tests/test_unified_rules.py

# write-then-read round-trip
python -c "import tempfile,sys; from pathlib import Path; sys.path.insert(0,'tests'); from conftest import unified_changeset_factory; from s19_app.tui.cdfx import write_unified_to_workarea, read_unified; d=Path(tempfile.mkdtemp()); cs=unified_changeset_factory('partial'); p,w=write_unified_to_workarea(cs,d,'rt.json'); b,r=read_unified(str(p),d); print('w',[i.code for i in w],'r',[i.code for i in r],'counts',cs.counts()==b.counts())"
```

---

## 4. Test results (actual output)

**`pytest -q tests/test_unified_read.py tests/test_unified_rules.py`** — all 25
pass:

```
.........................                                               [100%]
25 passed in 0.72s
```

**`pytest -q`** (full suite):

```
27 snapshots passed.
717 passed, 2 skipped, 3 xfailed in 186.87s (0:03:06)
```

Baseline was 692 passed / 2 skipped / 3 xfailed / 0 failed (increment-5 state).
Increment 6 adds the 25 new tests (16 in `test_unified_read.py`, 9 in
`test_unified_rules.py`) → **717 passed / 2 skipped / 3 xfailed / 0 failed**.
The 2 skips and 3 xfails are the unchanged baseline ones.

**`py_compile`** — `PY_COMPILE_OK` (all five files compile clean; `ruff` is not
installed, `py_compile` is the substitute per the task brief).

**Import surface** — `IMPORT_OK`, `__all__` now includes `read_unified`
alongside `serialize_unified` and `write_unified_to_workarea`.

**Write-then-read round-trip** — actual output:

```
ROUNDTRIP — write issues: [] read issues: []
counts match: True (8, 1)
parameter values exact ==: True
memory byte runs exact: True
```

A `UnifiedChangeSet` written by `write_unified_to_workarea` and read back by
`read_unified` recovers identical per-half counts, byte-exact parameter values
(including the three adversarial IEEE binary64 floats — `0.1`, the denormal
`5e-324`, the 17-digit value), and the exact ordered `new_bytes` run on every
memory entry, with no issues either way. (TC-025 in increment 9 is the formal
round-trip verdict; this is a smoke check.)

**Safety-path actual output** (from the verification runs):

```
truncated     -> ['MF-JSON-PARSE']     empty: True
garbage       -> ['MF-JSON-PARSE']     empty: True
bare-list     -> ['MF-BAD-STRUCTURE']  empty: True
bare-int      -> ['MF-BAD-STRUCTURE']  empty: True
bare-string   -> ['MF-BAD-STRUCTURE']  empty: True
no-halves     -> ['MF-BAD-STRUCTURE']  empty: True
deep (120k)   -> ['MF-JSON-PARSE']     empty: True   (no escaping RecursionError)
unresolved    -> ['MF-PATH-UNRESOLVED'] empty: True
no-address    -> ['MF-NO-ADDRESS']     mem count: 1  (clean entry kept)
empty-bytes   -> ['MF-EMPTY-BYTES']    mem count: 1
byte-range    -> ['MF-BYTE-RANGE']     mem count: 1
version-unknown -> ['MF-VERSION-UNKNOWN'] mem count: 1
entry-count   -> ['MF-ENTRY-LIMIT']    mem count: 100000  (== ceiling)
run-length    -> ['MF-ENTRY-LIMIT']    mem count: 2       (over-run entry dropped)
size-cap      -> ['MF-SIZE-CAP']       empty: True (json.load never reached)
```

Every adversarial input — a deeply-nested JSON document, an over-ceiling file,
a wrong-shape document — produces a deterministic collected issue with no
escaping `RecursionError` / `KeyError`. The TC-014 (`KeyError`) and TC-035
(`RecursionError`) tests assert the *absence of the escape* as the load-bearing
assertion: the test binds the return tuple, which only succeeds if the call
returned normally.

---

## 5. Risks

- **Pinned ceiling values are a judgement call.** `MF_ENTRY_COUNT_CEILING`
  (100_000) and `MF_RUN_LENGTH_CEILING` (1_048_576) are documented headroom
  picks, not spec-mandated numbers — LLR-006.5 explicitly defers the concrete
  values to Phase 3. They are generous (a realistic patch set is hundreds of
  entries / a realistic edit is thousands of bytes) so they will not reject a
  genuine file, while still capping the resource-exhaustion vector. If a future
  use legitimately exceeds either, the constant is a one-line change with the
  test fixture re-deriving from the module — low risk, easy to revisit.
- **`size_probe` default resolution.** `read_unified` resolves a `None`
  `size_probe` to a real `Path.stat().st_size` *at call time*, mirroring the
  increment-5 `copy_fn` seam pattern. Production callers leave it `None`; the
  TC-022 test injects an over-cap probe. Low residual risk.
- **Persisted `status` is intentionally not trusted.** The reader decodes the
  parameter `status` leniently (`_coerce_resolution_status` falls back to
  `UNRESOLVED_NO_A2L` for an unknown token) and adds every memory entry with
  the default `UNVALIDATED_NO_IMAGE` status — the real verdict is re-derived
  against the loaded image / A2L (A-7). The increment-9 TC-025 round-trip
  equality predicate already excludes the status field, so this is the
  intended behaviour, not a defect. The on-disk `status` is informational only.
- **`resolve_input_path` does not reject symlinks.** Per A-6 and LLR-006.3
  this is in-threat-model for a local single-user offline tool — reading a
  unified file *through* a symbolic link is accepted. The read-path security
  boundary is the size cap, the decoded-structure ceiling and the
  malformed/mis-shaped tolerance, all of which this increment carries and
  tests. Not a defect; flagged for the security-reviewer pass.
- **`json.load` C-recursion depth is platform-dependent.** The 120_000-deep
  `make_deeply_nested_unified_file` fixture is far past any platform's stdlib
  recursion limit, so the `RecursionError` arm is genuinely exercised on every
  OS. If a future stdlib raised a different exception type for deep nesting the
  test would catch the regression (the binding would fail).

---

## 6. Pending items

- **Selective export (increment 7).** `export_unified` — the coordinator that
  re-resolves the parameter half via `resolve_against_a2l`, calls the unchanged
  `write_cdfx_to_workarea`, writes the memory-field JSON file, and tags per-half
  issues on `ValidationIssue.artifact`. Increment 7 consumes the
  `unified_io.py` write half and the increment-5 serialize helper.
- **Round-trip formal verdict (increment 9).** TC-025 is the formal write→read
  round-trip test with exact `==` on parameter values and exact byte sequences;
  the smoke check in §4 above is not the formal verdict. Any write/read defect
  surfaces there.
- **Security-reviewer hand-off.** Per the plan §D and the cross-functional
  rule, increment 6 carries the read-path resource bounds — the 256 MB size
  cap, the decoded-structure ceiling, the `RecursionError` catch and the
  collect-don't-abort tolerance. This is a Phase-2 security-reviewer hand-off
  surface (§5.5); increments 5–7 should get one combined `security-reviewer`
  pass before merge.

---

## 7. Suggested next task

**Increment 7 — Selective export coordinator.** Add `s19_app/tui/cdfx/export.py`
with `export_unified(changeset, base_dir, a2l_tags, ...)`: re-resolve the
parameter half against the loaded A2L via `resolve_against_a2l`
(export-time-only, never persisted — A-7 / DD-11), invoke the **unchanged**
batch-03 `write_cdfx_to_workarea` with that `ChangeList` + `ResolutionResult`,
write the memory-field-half JSON via a `write_memory_field_to_workarea` helper
(reusing the increment-5 serialize-to-temp-then-`copy_into_workarea` pattern),
and tag each half's issues with `ValidationIssue.artifact` (`param-half` /
`memory-half` — no model change, C-5). Add `tests/test_unified_export.py`
(TC-028, TC-029, TC-030 incl. the `writer.py`-byte-unchanged check, TC-031,
TC-036) and re-export `export_unified`. Covers LLR-007.1..LLR-007.5.
