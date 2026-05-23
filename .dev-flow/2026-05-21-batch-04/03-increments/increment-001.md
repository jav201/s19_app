# Increment 001 — Review Packet — s19_app — batch-04

**Phase:** 3 — Implementation
**Increment:** 1 of 9 — Memory-change model + Phase-2 closure doc fixes
**Date:** 2026-05-21
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**Spec:** [`increment-plan.md` §B](increment-plan.md) — Increment 1 (FULL DETAIL)

---

## 1. What changed

Built the pure data layer of the batch-04 memory-field change kind: a new
`s19_app/tui/cdfx/memory.py` module holding `MemoryStatus` (a `str`-enum:
`inside` / `partial` / `outside` / `unvalidated-no-image`), the `MemoryChange`
dataclass (an address-keyed entry with an immutable `tuple[int, ...]`
`new_bytes` run, a construction-time `ValueError` on a malformed run, and an
`addressed_range` half-open-span property), and the `MemoryChangeList`
collection (address-keyed, insertion-ordered `dict` with `add` / `edit` /
`remove` / `get` / `entries` / `__len__` / `__contains__` — mirroring the
batch-03 `ChangeList` exactly). The module is pure stdlib — no XML, JSON, or
Textual import. The three new public symbols are re-exported from
`cdfx/__init__.py` and its package docstring now records the broadened scope.
A `memory_change_factory` generator (plus the pinned `MEMORY_OVERLAP_PAIR`
constant) was added to `tests/conftest.py`, and a new
`tests/test_memory_changelist.py` covers TC-001..TC-004 and the three TC-008
`ValueError` arms (20 tests). Finally, the two Phase-2 closure doc fixes were
folded into `01-requirements.md` — CV-01 (TC-010's expected result now asserts
the exact `.` / `0x2E` placeholder) and CV-02 (the §5.2 HLR-008 row now lists
TC-020); no normative `Statement:` bullet was touched.

## 2. Files modified

| # | File | Change | Purpose |
|---|------|--------|---------|
| 1 | `s19_app/tui/cdfx/memory.py` | **new** | `MemoryStatus` enum, `MemoryChange` dataclass (`__post_init__` `ValueError`, `addressed_range`), `MemoryChangeList` collection. Pure stdlib. |
| 2 | `s19_app/tui/cdfx/__init__.py` | edit | Re-export `MemoryChange` / `MemoryChangeList` / `MemoryStatus`; package docstring updated to record the memory-field / unified-change-set scope. |
| 3 | `tests/conftest.py` | edit | Added `memory_change_factory` + `MEMORY_OVERLAP_PAIR` (overlap pair pinned `0x100 len 8` + `0x104 len 8`, distinct address keys); added `MemoryChangeList` to the `TYPE_CHECKING` import. |
| 4 | `tests/test_memory_changelist.py` | **new** | TC-001..TC-004 + TC-008 `ValueError` arms — 20 tests. |
| 5 | `.dev-flow/2026-05-21-batch-04/01-requirements.md` | edit | CV-01 (TC-010 §5.7 + §5.3 rows assert the exact `.` placeholder) and CV-02 (§5.2 HLR-008 row adds TC-020). Cosmetic — no normative bullet touched. |

File count: **5 of 5** — within the cap.

## 3. How to test

```powershell
# 1. Compile the new/changed Python files (ruff substitute — ruff not installed)
python -m py_compile s19_app/tui/cdfx/memory.py s19_app/tui/cdfx/__init__.py tests/conftest.py tests/test_memory_changelist.py

# 2. Confirm the cdfx package imports cleanly (the new module is import-only)
python -c "import s19_app.tui.cdfx"

# 3. Run the new test file in isolation
python -m pytest -q tests/test_memory_changelist.py

# 4. Run the full suite (baseline 611 + 20 new = 631, 0 failed)
python -m pytest -q
```

## 4. Test results (actual output)

**`py_compile` + import** (ruff substitute):
```
PY_COMPILE_OK
IMPORT_OK ['ChangeList', 'ChangeListEntry', 'MemoryChange', 'MemoryChangeList', 'MemoryStatus', 'ResolutionStatus', 'read_cdfx', 'validate_w_rules', 'write_cdfx', 'write_cdfx_to_workarea']
```

**New test file** (`tests/test_memory_changelist.py`):
```
....................                                                     [100%]
20 passed in 0.08s
```

**Full suite** (`pytest -q`):
```
27 snapshots passed.
631 passed, 2 skipped, 3 xfailed in 181.18s (0:03:01)
```

Baseline was **611 passed / 2 skipped / 3 xfailed / 0 failed**. After this
increment: **631 passed / 2 skipped / 3 xfailed / 0 failed** — exactly +20 (the
new test file), 0 regressions, the skipped/xfailed counts unchanged.

Note: `ruff` is not installed in this environment; `python -m py_compile` was
substituted as instructed and passed on all four touched Python files.

## 5. Risks

- **Ordering choice (LLR-001.4).** `MemoryChangeList` pins **insertion order**
  via an `address`-keyed `dict`, identical to batch-03 `ChangeList`. TC-003
  asserts both that two reads of `entries` match *and* the exact order
  (`[0x300, 0x100, 0x200]`, not ascending) — a regression to ascending-address
  ordering fails it.
- **`new_bytes` storage type.** Stored as an immutable `tuple[int, ...]`;
  `__post_init__` coerces and validates. TC-001 explicitly asserts
  `isinstance(entry.new_bytes, tuple)` so a regression to a mutable `list`
  fails. Edge case not exercised here: an extremely long run — there is no
  ceiling at the model layer (that is the increment-6 `MF-ENTRY-LIMIT`
  read-path bound, by design; the model is pure data).
- **`edit` validate-before-mutate.** `MemoryChangeList.edit` builds a throw-away
  `MemoryChange` to validate the new run before touching the live entry, so a
  malformed-run edit raises `ValueError` and leaves the entry intact
  (`test_tc008_malformed_run_rejected_via_changelist_edit` pins this).
- **Doc edits.** CV-01/CV-02 touched only three table rows (§5.2 HLR-008, §5.7
  TC-010, §5.3 LLR-003.2) — all cosmetic/coverage wording. No HLR/LLR
  `Statement:` bullet was altered; the requirement set stays 5 US / 9 HLR /
  37 LLR / 37 TC.
- **`memory_change_factory` deferral.** Per plan §B.5, the factory ships only
  the bare-list build path (the `0x200` entry + the overlap pair). The
  range-coupled `inside` / `partial` / `outside` / gap-spanning variants and
  `make_ranged_s19` are deferred to increment 2 where they are first
  *consumed*. The factory's pinned addresses are documented as chosen relative
  to the increment-2 `make_ranged_s19` convention.

## 6. Pending items

- **Increment 2** must add `make_ranged_s19` and the range-coupled
  `memory_change_factory` variants (gap-spanning, partial, outside) — the
  factory docstring and conftest comment already flag this deferral.
- TC-008's **overlap arm** (the inter-entry overlap warning) is increment 2 —
  it needs the loaded-image validator. Increment 1 covers only the three
  construction-time `ValueError` arms, as scoped.
- No app wiring: `memory.py` is import-only this increment; the Patch Editor
  extension is increment 8.

## 7. Suggested next task

**Increment 2 — Memory-change validation against the loaded image.** Add
`s19_app/tui/cdfx/memory_validate.py` with `validate_memory_changes` (stamps
each entry's `MemoryStatus` against `LoadedFile.ranges`; emits one
warning-level `ValidationIssue` per `partial` / `outside` entry and per
overlapping-entry pair, address-only messages per C-9/S-006), add
`make_ranged_s19` and the range-coupled `memory_change_factory` variants to
`conftest.py`, re-export `validate_memory_changes`, and cover TC-005..TC-007
plus the TC-008 overlap arm. Consumes `LoadedFile` and `range_index.py`
read-only; depends only on this increment.
