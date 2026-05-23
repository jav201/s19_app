# Increment 002 — Review Packet — s19_app — batch-04

**Phase:** 3 — Implementation
**Increment:** 2 of 9 — Memory-change validation against the loaded image
**Date:** 2026-05-21
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**Spec:** [`increment-plan.md` §C](increment-plan.md) — Increment 2

---

## 1. What changed

Built the loaded-image validation layer for the batch-04 memory-field change
kind: a new `s19_app/tui/cdfx/memory_validate.py` module holding
`validate_memory_changes(memory_change_list, loaded_file_ranges)`. The function
stamps every `MemoryChange` entry with a `MemoryStatus` verdict against the
loaded firmware image's address ranges — `inside` (the addressed byte run lies
fully within one loaded range), `partial` (the run overlaps the ranges but is
not contained in a single one — the single verdict for both a range-edge
straddle and a gap-spanning run that touches two or more ranges), `outside`
(the run overlaps no loaded range), and `unvalidated-no-image` when no image is
loaded (`None` or empty ranges). It then collects `ValidationIssue` findings:
exactly one warning per `partial`/`outside` entry and exactly one per
overlapping entry, following the collect-don't-abort contract — it never raises
on a data-quality fault. Issue messages reference only the entry's `address`
and a byte-count summary, never the raw `new_bytes` content (constraint C-9).
Range membership reuses the `range_index.py` binary-search primitive
(`build_sorted_range_index` / `range_in_sorted_ranges`); the loaded image is
consumed read-only through its `ranges` snapshot, with no engine change and no
file-type branching.

`validate_memory_changes` is re-exported from `cdfx/__init__.py` (package
docstring updated to record the new `memory_validate` module). `conftest.py`
gained `make_ranged_s19` (a tiny header-less synthetic S19 with two disjoint,
gap-separated 128-byte ranges, pinned as `RANGED_S19_RANGES`), a `ranged_s19`
fixture that loads it through the real `load_service`, and the range-coupled
`memory_change_factory` variants (`partial` / `outside` / `gap-spanning`)
deferred from increment 1 — the no-arg `"base"` default is unchanged so the
increment-1 tests stay green. A new `tests/test_memory_validate.py` covers
TC-005, TC-006, TC-007, the TC-008 overlap arm, and LLR-008.3 (19 tests).

## 2. Files modified

| # | File | Change | Purpose |
|---|------|--------|---------|
| 1 | `s19_app/tui/cdfx/memory_validate.py` | **new** | `validate_memory_changes` + the private `_range_status` / `_range_issue` / `_overlap_issues` helpers; `MEMV-*` issue codes and the `memory-change` artifact tag. Reuses `range_index.py`; consumes `LoadedFile.ranges` read-only. |
| 2 | `s19_app/tui/cdfx/__init__.py` | edit | Re-export `validate_memory_changes`; package docstring records the `memory_validate` module. |
| 3 | `tests/conftest.py` | edit | Added `make_ranged_s19` + `RANGED_S19_RANGES` + the `ranged_s19` fixture; extended `memory_change_factory` with the `partial` / `outside` / `gap-spanning` variants (no-arg `"base"` default unchanged); added `LoadedFile` to the `TYPE_CHECKING` import. |
| 4 | `tests/test_memory_validate.py` | **new** | TC-005, TC-006, TC-007, TC-008 (overlap arm), LLR-008.3 — 19 tests. |

File count: **4 of 5** — within the cap (the §C reserve slot
`tests/test_memory_changelist.py` was not needed; the TC-008 overlap arm is
co-located in the new validation test file with the rest of HLR-002).

## 3. How to test

```powershell
# 1. Compile the new/changed Python files (ruff substitute — ruff not installed)
python -m py_compile s19_app/tui/cdfx/memory_validate.py s19_app/tui/cdfx/__init__.py tests/conftest.py tests/test_memory_validate.py

# 2. Confirm the cdfx package imports cleanly (the new module is import-only)
python -c "import s19_app.tui.cdfx"

# 3. Run the new test file in isolation
python -m pytest -q tests/test_memory_validate.py

# 4. Run the full suite (baseline 631 + 19 new = 650, 0 failed)
python -m pytest -q
```

## 4. Test results (actual output)

**`py_compile` + import** (ruff substitute):
```
PY_COMPILE_OK
IMPORT_OK ['ChangeList', 'ChangeListEntry', 'MemoryChange', 'MemoryChangeList', 'MemoryStatus', 'ResolutionStatus', 'read_cdfx', 'validate_memory_changes', 'validate_w_rules', 'write_cdfx', 'write_cdfx_to_workarea']
```

**New test file** (`tests/test_memory_validate.py`):
```
...................                                                      [100%]
19 passed in 0.14s
```

**Full suite** (`pytest -q`):
```
27 snapshots passed.
650 passed, 2 skipped, 3 xfailed in 180.72s (0:03:00)
```

Baseline was **631 passed / 2 skipped / 3 xfailed / 0 failed**. After this
increment: **650 passed / 2 skipped / 3 xfailed / 0 failed** — exactly +19 (the
new test file), 0 regressions, the skipped/xfailed counts unchanged.

Note: `ruff` is not installed in this environment; `python -m py_compile` was
substituted as instructed and passed on all four touched Python files.

Two test failures surfaced on the first run and were fixed before this packet:
- `make_ranged_s19` initially wrote an S0 header record; `S19File` maps the S0
  payload as data at address 0, producing a spurious `(0, 6)` range. The S0
  header was dropped — `S19File` parses a header-less file cleanly (verified) —
  so `LoadedFile.ranges` is now exactly the two documented ranges.
- A C-9 test asserted no byte value appeared as a *decimal* token; the decimal
  form of byte `0xBE` (190) collided with the address `0x190`. The assertion
  was narrowed to the two-digit *hex* form — the form a leaked byte would
  actually take in a message — since the messages never render bytes in
  decimal. The C-9 intent is unchanged.

## 5. Risks

- **`partial` vs `outside` boundary (LLR-002.1).** `_range_status` first asks
  the binary-search index whether the whole run fits one range (`inside`); if
  not, it scans for any byte-level intersection with any range — one or more
  intersections → `partial`, none → `outside`. The half-open intersection test
  `start < range_end and range_start < end` is the standard correct form;
  TC-005's four arms (inside / edge-straddle partial / gap outside /
  gap-spanning partial) pin every branch. A regression that classified a
  gap-spanning run as one status per range would fail
  `test_tc005_gap_spanning_entry_is_a_single_partial`.
- **Gap-spanning single-issue rule (LLR-002.2).** Because the gap-spanning run
  resolves to one `partial` entry, `_range_issue` emits exactly one issue for
  it — `test_tc006_gap_spanning_entry_collects_exactly_one_warning` asserts
  the count is 1, so a "one issue per touched range" regression fails.
- **Overlap issue cardinality (LLR-002.4).** `_overlap_issues` records each
  overlapping entry once (a `setdefault` per side) and emits one issue per
  recorded entry — so an intersecting pair yields **two** issues, one per
  address. This matches the LLR-002.4 wording ("one `ValidationIssue` for each
  ... entry whose ... range overlaps"). An entry overlapping multiple partners
  still gets one issue (naming the first partner found); the requirement does
  not ask for one issue per pair, and no TC exercises a 3-way overlap — flagged
  as a known interpretation, not a defect.
- **`make_ranged_s19` ranges are pinned.** `RANGED_S19_RANGES` (`[0x100,0x180)`
  + `[0x200,0x280)`, gap `[0x180,0x200)`) is a module-level constant;
  `test_tc005_validator_reads_loadedfile_ranges_no_reparse` asserts the loaded
  `LoadedFile.ranges` equals it exactly, so a fixture drift is caught. The
  `memory_change_factory` variant addresses are chosen relative to these
  boundaries and documented in the conftest section comment.
- **No engine change (C-2).** `core.py`, `models.py`, `range_index.py`,
  `validation/model.py` are imported and called only; none was edited.
  `memory.py` (increment 1) is untouched.

## 6. Pending items

- **Increment 3** — `memory_display.py` (`format_memory_value` — hex / ASCII /
  decimal renderings); depends only on increment 1.
- **Increment 4** — `UnifiedChangeSet` container; will consume
  `memory_change_factory` (including the variants added here) via the
  `unified_changeset_factory`.
- The `unified_changeset_factory`, `make_unified_file` and the read/write
  fixtures named in the §5.4 catalogue are not added yet — they are introduced
  by the increments that first consume them (4–6), per the plan.
- No app wiring: `memory_validate.py` is import-only this increment; the Patch
  Editor extension is increment 8.

## 7. Suggested next task

**Increment 3 — Memory-change value display.** Add
`s19_app/tui/cdfx/memory_display.py` with `format_memory_value` — a pure,
non-mutating renderer producing the hex-primary form (uppercase two-digit
space-separated), the ASCII companion (each byte 0x20–0x7E as its character,
every other byte as the pinned `.` / 0x2E placeholder per CV-01), and the
decimal companion (space-separated). Re-export the entry point from
`cdfx/__init__.py`, add `tests/test_memory_display.py` covering TC-009, TC-010
(incl. the exact `.` placeholder), and TC-011 (stored bytes byte-identical
before/after every render). Depends only on increment 1 (`MemoryChange.new_bytes`).
