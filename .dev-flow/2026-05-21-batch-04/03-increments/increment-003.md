# Increment 003 — Memory-change value display — Review Packet

**Phase:** 3 — Implementation
**Batch:** 2026-05-21-batch-04
**Increment:** 3 of 9 — Memory-change value display
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-003.1, LLR-003.2, LLR-003.3
**TCs covered:** TC-009, TC-010, TC-011

---

## 1. What changed

Added the pure display layer for the memory-change kind: a new module
`s19_app/tui/cdfx/memory_display.py` exposing `format_memory_value(new_bytes)`,
which renders a `MemoryChange`'s stored byte run into three positionally-aligned
display forms — **hex** (the primary form: two-digit uppercase, space-separated),
**ASCII** (each printable byte 0x20–0x7E as its character, every other byte as
the pinned `.` / 0x2E placeholder), and **decimal** (space-separated decimal byte
values). The three forms are returned bundled in a frozen `MemoryValueRendering`
dataclass. The function is pure — it reads `new_bytes` strictly by iteration, has
no XML/JSON/Textual/file-I/O dependency, imports stdlib only, and never mutates
the source bytes (LLR-003.3). The two new public symbols are re-exported from
`cdfx/__init__.py` so the package keeps one narrow import surface. A new test
file `tests/test_memory_display.py` exercises TC-009 / TC-010 / TC-011, with
TC-010 asserting the *exact* `.` placeholder character (the CV-01 closure
clause). `memory.py`, `memory_validate.py` and the engine were not touched.

## 2. Files modified

| # | File | Change | Purpose |
|---|------|--------|---------|
| 1 | `s19_app/tui/cdfx/memory_display.py` | **New** | `format_memory_value` + `MemoryValueRendering` + `_ascii_char` helper; `ASCII_PLACEHOLDER` / printable-range constants. Pure hex / ASCII / decimal rendering of a memory-change byte run. |
| 2 | `s19_app/tui/cdfx/__init__.py` | **Edit** | Re-export `format_memory_value` and `MemoryValueRendering`; add `memory_display` to the package docstring's module list. |
| 3 | `tests/test_memory_display.py` | **New** | TC-009 (hex), TC-010 (ASCII + decimal + exact `.` placeholder), TC-011 (no mutation) — 12 test functions. |

3 files — within the ≤5 cap.

## 3. How to test

Run from the repo root `C:\Users\jjgh8\Github\s19_app`:

```
python -m py_compile s19_app/tui/cdfx/memory_display.py s19_app/tui/cdfx/__init__.py tests/test_memory_display.py
python -c "import s19_app.tui.cdfx"
python -m pytest -q tests/test_memory_display.py
python -m pytest -q
```

(`ruff` is not installed in this environment; `python -m py_compile` is the
substituted static check per the increment brief.)

## 4. Test results (actual output)

**`py_compile`** (all three files):
```
PY_COMPILE_OK
```

**`python -c "import s19_app.tui.cdfx"`**:
```
IMPORT_OK
['ChangeList', 'ChangeListEntry', 'MemoryChange', 'MemoryChangeList', 'MemoryStatus',
 'MemoryValueRendering', 'ResolutionStatus', 'format_memory_value', 'read_cdfx',
 'validate_memory_changes', 'validate_w_rules', 'write_cdfx', 'write_cdfx_to_workarea']
```

**`pytest -q tests/test_memory_display.py`**:
```
............                                                             [100%]
12 passed in 0.08s
```

**`pytest -q` (full suite)**:
```
27 snapshots passed.
662 passed, 2 skipped, 3 xfailed in 188.62s (0:03:08)
```

Baseline was 650 passed / 2 skipped / 3 xfailed / 0 failed. After this
increment: **662 passed** (+12 new memory-display tests) / 2 skipped / 3 xfailed
/ **0 failed**. No regressions; the suite stays green.

## 5. Risks

- **Low overall** — the module is a pure deterministic byte-to-text mapping with
  no I/O, no shared state, and no engine coupling.
- The single pinned-detail risk (the ASCII placeholder) is closed: `.` (0x2E)
  is fixed as the `ASCII_PLACEHOLDER` constant, and TC-010 asserts that exact
  character four ways — `== "."`, `== "\x2e"`, `ord(...) == 0x2E`, and
  `== ASCII_PLACEHOLDER`. The printable range is inclusive 0x20–0x7E, with a
  boundary test (0x20/0x7E inside, 0x1F/0x7F outside).
- ASCII positional alignment (one character per byte) is enforced by joining the
  ASCII characters with no separator and is pinned by a length-equality test, so
  the ASCII string lines up token-for-token with the hex form.
- **Edge case not covered by a TC, handled defensively:** an empty `new_bytes`
  sequence renders as three empty strings rather than raising. In practice
  `MemoryChange.__post_init__` already rejects an empty run at construction
  (LLR-002.5), so a byte run reaching `format_memory_value` is always non-empty;
  the empty-input behaviour is documented in the docstring but is not a normal
  path.
- `format_memory_value` accepts any `Sequence[int]` and assumes well-formed
  bytes (0–255). It does not re-validate byte ranges — that is `MemoryChange`'s
  construction-time contract (LLR-002.5, increment 1). A caller passing a raw
  out-of-range list directly (bypassing `MemoryChange`) would get a malformed
  hex token; this is acceptable since the documented input is a `MemoryChange`
  byte run, but worth noting for increment 8's UI wiring.

## 6. Pending items

- None within this increment's scope. All three LLRs (003.1/003.2/003.3) and all
  three TCs (009/010/011) are implemented and green.
- `format_memory_value` is import-only — not yet wired into any screen. The
  Patch Editor consumption of this function is increment 8 (LLR-009.1), as
  planned.

## 7. Suggested next task

**Increment 4 — Unified change-set container.** Create
`s19_app/tui/cdfx/changeset.py` with `UnifiedChangeSet` composing a batch-03
`ChangeList` (parameter half) and a `MemoryChangeList` (memory half) as distinct
attributes — per-half access, independent mutation, `counts()`, `is_empty()`;
compose, do not subclass (constraint C-3). Re-export from `cdfx/__init__.py`, add
the `unified_changeset_factory` to `tests/conftest.py`, and add
`tests/test_unified_changeset.py` (TC-012, TC-013, TC-026). Depends only on
increment 1; independent of increments 2 and 3.

---

*Stopping at the increment boundary — increment 4 not started.*
