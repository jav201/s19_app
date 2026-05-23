# Increment 005 — `Optional[int]` change-list model + resolver migration

> **Phase 3 · batch-03 · Increment 5.** Migration of the already-shipped
> change-list model and A2L resolver to the Phase-3 amended contract
> (`array_index: Optional[int]`). Spec: increment-plan §A.3; requirements
> LLR-001.1 / LLR-001.3 / LLR-002.3 (amended). Branch:
> `dev-flow/batch-02-direction-b-restyle`.

## 1. What changed

`ChangeListEntry.array_index` was migrated from `int` (default `0`) to
`Optional[int]` (default `None`): `None` now means a scalar (`VALUE` /
`BOOLEAN`) or ASCII-string parameter, an integer *k* means element *k* of a
1-D array. The entry-identity type alias `EntryKey` was widened from
`tuple[str, int]` to `tuple[str, int | None]`, which makes `(name, None)` (a
scalar entry) and `(name, 0)` (array element 0) **distinct** dedup identities —
the unambiguous scalar-vs-array discriminator the writer (increment 6) and
reader (increment 7) require. The `add` / `edit` / `remove` / `get` methods
default `array_index` from `0` to `None`. In the resolver, the LLR-002.3
array-index range check is now guarded by `isinstance(array_index, int)` so a
`None`-index (scalar/string) entry resolves on name alone and skips the check —
without the guard, `None < 0` would raise `TypeError` and crash every scalar
entry's resolution. The two test modules were migrated to the `Optional[int]`
shape: scalar/string entries are built with `array_index=None`, array elements
keep their integer indices, the `change_list_factory` helper was updated to the
new shape, and the TC-001/TC-002/TC-006 catalogue rows were re-verified
(including new assertions that `(name, None) ≠ (name, 0)`). The CV-02 / CV-03
cosmetic doc/comment items were applied opportunistically in the two test
files. No behavior change to dedup or ordering beyond the key-type widening; no
new XML, reader, or UI code.

## 2. Files modified

| File | Purpose of change |
|------|-------------------|
| `s19_app/tui/cdfx/changelist.py` | `array_index` `int`→`Optional[int]` (default `None`); `EntryKey` → `tuple[str, int \| None]`; `add`/`edit`/`remove`/`get` default `0`→`None`; `import typing.Optional` added; `ChangeListEntry`/`ChangeList` docstrings (Args, Example, class summary) rewritten to the `None`-is-scalar/string contract. |
| `s19_app/tui/cdfx/resolve.py` | `_resolve_entry` range-checks `array_index` only when `isinstance(..., int)` — a `None` index skips the LLR-002.3 check and resolves on name alone; `_resolve_entry`/`resolve_against_a2l` docstrings updated. `_element_count_of` unchanged. |
| `tests/test_cdfx_changelist.py` | `change_list_factory` migrated (scalar/string carry `array_index=None`, array carries `(name,k)`); TC-001 split into array-element / scalar-`None` / ASCII-`None` / distinct-identity arms; TC-002 scalar calls migrated to `None` and a new `(name,None)≠(name,0)` dedup assertion added; TC-003/TC-010 scalar calls migrated; module docstring tightened (CV-02). |
| `tests/test_cdfx_resolve.py` | TC-004/005/007 scalar-entry calls migrated to `array_index=None`; TC-006 scalar arm rewritten to `array_index=None` and renamed `test_tc006_scalar_none_index_resolves_without_range_check` (proves the `isinstance` guard); module docstring TC-006 row tightened (CV-03). Integer-index array arms (TC-004 array, TC-006 index 5/-1/2/9) unchanged. |

Exactly 4 files — within the ≤5 cap. `writer.py`, `display.py` and their tests
were **not** touched (see Risks).

## 3. How to test

```bash
# the two migrated modules
python -m pytest -q tests/test_cdfx_changelist.py tests/test_cdfx_resolve.py

# full suite — must hold green
python -m pytest -q

# package import (no XML / Textual added)
python -c "import s19_app.tui.cdfx"

# compile-check (ruff not installed — py_compile substituted per the brief)
python -m py_compile s19_app/tui/cdfx/changelist.py s19_app/tui/cdfx/resolve.py \
  tests/test_cdfx_changelist.py tests/test_cdfx_resolve.py
```

## 4. Test results — actual output

`py_compile` of all four files: **`PY_COMPILE_OK`** (no error).
`python -c "import s19_app.tui.cdfx"`: **`IMPORT_OK`**.
TUI entry point: `import s19_app.tui` succeeds, `main` is callable.

Two migrated modules:

```
.................................                                        [100%]
33 passed in 0.15s
```

Full suite:

```
27 snapshots passed.
502 passed, 2 skipped, 3 xfailed in 171.17s (0:02:51)
```

**0 failed, 0 errored.** The full-suite baseline before this increment was
**499 passed / 2 skipped / 3 xfailed**. After the migration it is **502 passed
/ 2 skipped / 3 xfailed** — `+3 passed`, no regression, the skip/xfail counts
are unchanged.

**On the +3 count delta (deviation from the brief's "no count drift" line).**
The brief said "the migration adds no tests"; the increment-plan §A.3 *body*,
however, explicitly instructs the TC-001 row to gain an ASCII-`None` arm and a
`(name, None) ≠ (name, 0)` distinct-identity arm, and the TC-002 row to gain a
scalar-vs-element-0 dedup assertion. Those are **re-verification of the
existing TC-001/TC-002 catalogue numbers under the migrated contract** — no new
TC *number* was created — but they are necessarily new `pytest` *functions*, so
the function count rose by 3 net inside `test_cdfx_changelist.py` (two new
TC-001 functions and one new TC-002 function added; the old
`test_tc001_scalar_entry_defaults_to_array_index_zero` was rewritten/renamed,
not deleted). `test_cdfx_resolve.py` count is unchanged. The "+3" is therefore
the §A.3 instruction set, not scope creep; flagged here so Phase 4 reads it as
a planned re-verification, not an unplanned addition.

## 5. Risks

- **Increment-4 writer tests build scalars with positional `array_index=0`.**
  `tests/test_cdfx_writer.py` and `tests/test_cdfx_w_rules.py` were **not**
  touched by this increment (4-file cap, increment-6 boundary). They still
  construct what were "scalar" entries with positional `array_index=0`. After
  this migration `0` semantically means **array element 0**, not a scalar — so
  those entries are **semantically stale**. They **stay green** in increment 5
  because the writer still emits one `SW-INSTANCE` per entry (coalescing is
  increment 6) and `0` is still a valid `int` for `Optional[int]`, so nothing
  type-fails or behaviour-fails. Increment 6's writer rework is where those
  tests are rewritten to `array_index=None` for scalars. **This is a planned,
  deferred test correction — Phase 4 should not read a stale `array_index=0`
  scalar in the increment-4 writer tests as a defect.** (Recorded identically
  in the increment plan §A.5 "stale-test note" and risk section.)
- **`EntryKey` widening / `dict` hashing.** `tuple[str, None]` and
  `tuple[str, int]` are both hashable and never collide; the backing `dict` is
  correct without change. Mitigated by the new TC-002 test
  `test_tc002_dedup_distinguishes_scalar_none_from_array_element_zero`, which
  fails loudly if the two keys ever collapse.
- **Resolver `None`-index arithmetic.** `None < 0` raises `TypeError` in
  Python 3. The `isinstance(index, int)` guard prevents it; the TC-006 scalar
  arm (`test_tc006_scalar_none_index_resolves_without_range_check`) exercises a
  `None`-index entry end-to-end and would fail (with a `TypeError`) if the
  guard were dropped — so the guard is test-pinned.
- **Edge case not covered by this increment.** The model *permits* a
  `(PARAM, None)` scalar entry and a `(PARAM, 0)` array entry to coexist for
  the same name. Per LLR-001.3's rationale a real A2L parameter is either
  scalar or array, never both, so this never legitimately happens; the model
  intentionally keeps them as two rows and invents no merge rule. The writer's
  handling of that (theoretical) coexistence is an increment-6 concern, called
  out in the increment-6 risk section — not handled speculatively here.
- **`writer.py` positional calls type-check silently.** Because `0` is a valid
  `int` for `Optional[int]`, no compiler/type error surfaces the staleness.
  This is by design (keeps increment 5 at 4 files) but means the staleness is
  only visible via this note, not via a failing test — hence the explicit
  Phase-4 callout above.

## 6. Pending items

- **Increment 6 — writer behaviour migration.** Rework `writer.py` to coalesce
  integer-`array_index` entries into one `VAL_BLK` `SW-INSTANCE`, treat
  `None`-index entries as scalar `VALUE`/`BOOLEAN`/`ASCII`, reject sparse
  arrays (`W-ARRAY-SPARSE`); rewrite `test_cdfx_writer.py` /
  `test_cdfx_w_rules.py` scalar fixtures from positional `array_index=0` to
  `array_index=None`. **Not started — increment 5 stops at its boundary.**
- The `change_list_factory` helper's relocation to `tests/conftest.py` and its
  adversarial-float arm remain deferred to increment 10 (per plan §A.4); the
  factory in `test_cdfx_changelist.py` was migrated in place this increment.
- `s19_app/tui/cdfx/__init__.py` re-export surface is unchanged
  (`ChangeList` / `ChangeListEntry` / `ResolutionStatus`); the `write_cdfx` /
  `read_cdfx` / `validate_w_rules` re-exports land in increment 7 per the plan.

## 7. Suggested next task

**Increment 6 — Writer coalescing rework + `W-ARRAY-SPARSE`.** Rework
`s19_app/tui/cdfx/writer.py` so entries are grouped by `parameter_name`:
integer-`array_index` groups coalesce into one `VAL_BLK` `SW-INSTANCE` with one
ascending-index `VG`, `None`-index entries stay one scalar/string
`SW-INSTANCE` each, and a non-contiguous / non-zero-based integer-index group
is rejected with a `W-ARRAY-SPARSE` warning. Rewrite the increment-4 writer
test fixtures to build scalars with `array_index=None` (clearing the stale-test
risk recorded in §5), add the TC-013 array arm and TC-038 sparse cases,
re-verify TC-012 / TC-019h. 3 files: `writer.py`, `test_cdfx_writer.py`,
`test_cdfx_w_rules.py`.
