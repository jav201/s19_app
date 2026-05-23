# Increment 4 — Unified change-set container — Review Packet

**Batch:** 2026-05-21-batch-04 — memory-field change kind + unified change-set + selective export
**Phase:** 3 — Implementation
**Increment:** 4 of 9 — unified change-set container
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**Date:** 2026-05-21
**LLRs covered:** LLR-004.1, LLR-004.2, LLR-004.3, LLR-004.4, LLR-004.5
**TCs covered:** TC-012, TC-013, TC-026 (contributes runtime corroboration to TC-027, finalized increment 9)

---

## 1. What changed

Added the unified change-set container — the single in-app object that holds
**both** change kinds of a patch set. `UnifiedChangeSet` (new module
`s19_app/tui/cdfx/changeset.py`) **composes** a batch-03 parameter `ChangeList`
and a batch-04 `MemoryChangeList` as two distinct member attributes
(`parameters` / `memory`) — it does **not** subclass either type, nor `dict`,
honouring constraint C-3 / LLR-004.2. It exposes `counts() -> tuple[int, int]`
(parameter count first, memory count second, never summed) and
`is_empty() -> bool` (true only when both halves are empty). The class is a
thin pure-data container: no validation, no JSON/XML, no Textual — those
concerns are the later increments (5-7). The new public symbol is re-exported
from `cdfx/__init__.py` so the import surface stays narrow. A
`unified_changeset_factory` was added to `tests/conftest.py`; it builds the
container by **composition** from the existing `change_list_factory` (parameter
half — the three adversarial IEEE floats are inherited from it, not re-declared
— Q-09 note) and `memory_change_factory` (memory half). The new test module
`tests/test_unified_changeset.py` covers TC-012 / TC-013 / TC-026 with 12
tests.

## 2. Files modified

| # | File | Purpose |
|---|------|---------|
| 1 | `s19_app/tui/cdfx/changeset.py` | **New.** `UnifiedChangeSet` — `__init__` builds an empty `ChangeList` + `MemoryChangeList`; `parameters` / `memory` attributes; `counts()`; `is_empty()`. Composes, never subclasses (C-3). |
| 2 | `s19_app/tui/cdfx/__init__.py` | **Edit.** Re-export `UnifiedChangeSet`; package docstring notes the new `changeset` module. |
| 3 | `tests/conftest.py` | **Edit.** Added `unified_changeset_factory(memory_variant="base")` — composes the parameter half from `change_list_factory` and the memory half from `memory_change_factory`; added `UnifiedChangeSet` to the `TYPE_CHECKING` import. |
| 4 | `tests/test_unified_changeset.py` | **New.** 12 tests covering TC-012 (both halves as distinct attributes, parameter half resolution-free), TC-013 (independent mutation, per-half counts `(1,2)`, empty-state), TC-026 (compose-not-subclass runtime corroboration). |

**File count: 4** — within the ≤5 cap.

**Byte-unchanged this increment (constraints C-1/C-2/C-3):** `cdfx/changelist.py`,
`cdfx/memory.py`, `cdfx/memory_validate.py`, `cdfx/memory_display.py`,
`cdfx/reader.py`, `cdfx/writer.py`, `cdfx/resolve.py`, `cdfx/display.py`,
`core.py`, `hexfile.py`, the engine. They are imported and called, never edited.

## 3. How to test

```powershell
# From the repo root C:\Users\jjgh8\Github\s19_app

# 1. Syntax / compile gate (ruff not installed — py_compile substitute)
python -m py_compile s19_app/tui/cdfx/changeset.py s19_app/tui/cdfx/__init__.py tests/conftest.py tests/test_unified_changeset.py

# 2. Package imports cleanly with the new symbol
python -c "import s19_app.tui.cdfx; print(s19_app.tui.cdfx.UnifiedChangeSet)"

# 3. The new increment-4 test module
python -m pytest -q tests/test_unified_changeset.py

# 4. Full suite — green gate
python -m pytest -q
```

## 4. Test results (actual output)

**`py_compile` + import check** (ruff substitute):
```
PY_COMPILE_OK
IMPORT_OK <class 's19_app.tui.cdfx.changeset.UnifiedChangeSet'>
```

**New test module `tests/test_unified_changeset.py`:**
```
............                                                             [100%]
12 passed in 0.08s
```

**Full suite `pytest -q`:**
```
27 snapshots passed.
674 passed, 2 skipped, 3 xfailed in 181.63s (0:03:01)
```

Baseline was **662 passed / 2 skipped / 3 xfailed / 0 failed**. After this
increment: **674 passed** (662 + 12 new) **/ 2 skipped / 3 xfailed / 0 failed**.
No regressions; the 2 skipped and 3 xfailed are the unchanged pre-existing
baseline state.

## 5. Risks

- **Low overall** — the increment is a thin pure-data container, no I/O, no
  parsing, no Textual.
- **C-3 compose-not-subclass** is the one constraint-sensitive point. It is
  guarded at runtime by `test_tc026_unified_change_set_is_not_a_subclass`
  (`issubclass` against `ChangeList` / `MemoryChangeList` / `dict`, all false)
  and `test_tc026_halves_are_instances_of_the_existing_list_types`. The
  byte-unchanged half of LLR-004.2 is a static fact finalized by the TC-027
  inspection checklist in increment 9 — not asserted here.
- **`unified_changeset_factory` count coupling.** The factory's composed counts
  `(8, 3)` are pinned in `test_tc026_factory_composes_both_source_factories`.
  If a future change to `change_list_factory` or `memory_change_factory`
  alters their entry counts, that test fails loudly — intended, so the
  downstream write/round-trip tests never silently rest on a changed fixture.
- **Edge case not covered here:** the `UnifiedChangeSet` carries no JSON
  serialization or validation — by design (increments 5-7). No empty-vs-`None`
  ambiguity exists since `__init__` always builds two real (empty) lists.

## 6. Pending items

- None for increment 4. All 5 LLRs (LLR-004.1..004.5) and 3 TCs
  (TC-012/013/026) are implemented and green.
- TC-027 (the compose-not-subclass *inspection* checklist, `changelist.py`
  byte-unchanged file-hash assertion) is deliberately deferred to increment 9
  per the increment plan — increment 4 supplies only the runtime corroboration.

## 7. Suggested next task

**Increment 5 — Unified change-set file write.** Create
`s19_app/tui/cdfx/unified_io.py` (write half): `serialize_unified(changeset)`
and `write_unified_to_workarea(changeset, base_dir, file_name)` — a JSON
document carrying format-id + version + both halves (memory half as the
LLR-005.3 array-of-objects, `address` an integer field never a key), using the
serialize-to-temp-then-`copy_into_workarea` containment pattern. Re-export from
`cdfx/__init__.py`, add `make_unified_file` to `conftest.py`, and add
`tests/test_unified_write.py` (TC-015/016/017/018). Define the `MF-*` code
constants in `unified_io.py` (the rule-code module home). LLRs LLR-005.1..005.4.
Note the §D security hand-off: increments 5-7 carry the write-path containment
and read-path resource bounds — request a `security-reviewer` pass over 5-7
before merge.
```
```

---

*Review packet generated per GRNDIA supervised-incremental-development workflow.
Increment boundary reached — stopping. Increment 5 not started.*
