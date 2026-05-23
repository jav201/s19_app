# Increment 001 — Parameter change-list model — Review Packet

> **Batch:** 2026-05-21-batch-03 · **Phase 3 (Implementation), Increment 1 of 9.**
> **Branch:** `dev-flow/batch-02-direction-b-restyle`.
> Spec: [`increment-plan.md` §3](./increment-plan.md) · Requirements:
> [`01-requirements.md`](../01-requirements.md) LLR-001.1..001.4, LLR-003.3 (model half).

---

## 1. What changed

Created the new `s19_app/tui/cdfx/` package and shipped the pure parameter
change-list model — the foundation every later CDFX increment depends on. The
model is `ResolutionStatus` (a 4-member `str`-enum), `ChangeListEntry` (a
slotted dataclass holding `parameter_name` / `array_index` / `value` /
`status`), and `ChangeList` (an identity-keyed container with `add` / `edit` /
`remove` / `get` and an ordered `entries` accessor). Entry identity is the
`(parameter_name, array_index)` pair; `add` on an existing identity updates in
place rather than duplicating. Ordering is **insertion order**, realised by a
`dict` keyed on `(parameter_name, array_index)` — pinned so increment 4's
writer can iterate the same `entries` accessor and reproduce `SW-INSTANCE`
order byte-identically with no second ordering rule. The module is pure data:
no A2L, no XML, no Textual imports — only `dataclasses` and `enum` from the
stdlib. A new test module exercises TC-001/002/003/010 (model arms) and begins
the `change_list_factory` test helper (resolved scalar/array/string arm only).

No A2L-type validation was added (that is resolution, increment 2). No runtime
dependency was added; `pyproject.toml` / `requirements.txt` are byte-unchanged.

CV-01..CV-03 (the Phase-2 cosmetic doc/test-comment items) touch no model logic
and were not opportunistically applied this increment — flagged in §6.

## 2. Files modified

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/cdfx/__init__.py` | new | Package init; re-exports `ChangeList`, `ChangeListEntry`, `ResolutionStatus` — the narrow public import surface. |
| `s19_app/tui/cdfx/changelist.py` | new | The model: `ResolutionStatus` enum, `ChangeListEntry` dataclass, `ChangeList` container with add/edit/remove/get + deterministic `entries`. Pure data. |
| `tests/test_cdfx_changelist.py` | new | TC-001/002/003/010 (model arms) + the `change_list_factory` helper (resolved scalar/array/string arm). 16 tests. |

3 files — within the ≤5 cap.

## 3. How to test

Run from the repo root `C:\Users\jjgh8\Github\s19_app`:

```
python -m pytest -q tests/test_cdfx_changelist.py     # the new module
python -m pytest -q                                   # full suite, no regression
python -c "import s19_app.tui"                        # tui package still imports
python -c "import s19_app.tui.cdfx"                   # new package imports
python -m py_compile s19_app/tui/cdfx/__init__.py s19_app/tui/cdfx/changelist.py tests/test_cdfx_changelist.py
```

`ruff` is **not installed** in this environment — `python -m py_compile` was
substituted as the static check on the three new files, as instructed.

## 4. Test results

Actual captured output:

- **`pytest -q tests/test_cdfx_changelist.py`** → `16 passed in 0.08s`.
- **`pytest -q` (full suite)** → `435 passed, 2 skipped, 3 xfailed in 182.36s`,
  `27 snapshots passed`, **0 failed**. Baseline was 419 passed / 2 skipped /
  3 xfailed; 419 + 16 new = 435 — exact, no regression.
- **`python -c "import s19_app.tui"`** → `IMPORT_TUI_OK` (clean exit).
- **`python -c "import s19_app.tui.cdfx"`** → `IMPORT_CDFX_OK` (clean exit).
- **`python -m py_compile` on the 3 new files** → `PY_COMPILE_OK` (clean exit).

The 16 new tests by TC:
- TC-001 (entry construction, LLR-001.1) — 3 tests: four-field readback, scalar
  `array_index == 0` default, `key` identity pair.
- TC-002 (add/edit/remove + dedup, LLR-001.2/001.3) — 8 tests: add-then-remove
  empties the list, edit is surgical, edit preserves status, double-add dedups,
  dedup distinguishes array index, edit/remove on a missing key raise `KeyError`.
- TC-003 (deterministic ordering, model arm, LLR-001.4) — 3 tests: repeated
  iteration is identical, order is insertion order (not sorted), in-place update
  keeps insertion position.
- TC-010 (physical-value storage arm, LLR-003.3) — 3 tests: stored value equals
  entered value, `value` accepts `int`/`float`/`str`/`None`, edit replaces
  verbatim.

## 5. Risks

- **Ordering rule is now load-bearing.** LLR-001.4 is pinned to insertion order
  via a `dict` keyed on `(name, index)`. Increment 4's writer **must** iterate
  the `ChangeList.entries` accessor and introduce no second ordering rule —
  `test_tc003_*` will catch a divergence at the model level but the writer's
  byte-identical guarantee depends on this reuse.
- **TC-003 / TC-010 are staged, not fully closed.** TC-003's "byte-identical
  `SW-INSTANCE`" verdict needs the real writer (increment 4); TC-010's
  "display derived" verdict needs `format_value` (increment 3). Increment 1
  lands only the model arm of each — recorded in the test module docstring so
  Phase 4 sees them as staged, not skipped. Not a defect; a planned split.
- **`value` is intentionally permissive.** Typed `int | float | str | None`
  with no A2L-type validation. An out-of-type or out-of-range value is not
  rejected here — that is resolution's job (increment 2). A caller that stores
  a nonsensical value before resolution runs will not be stopped by the model.
- **`edit`/`remove` raise `KeyError` on a missing identity.** Chosen as
  fail-loud per the project rules. Increment 7's Patch Editor must catch these
  and surface them on the status path rather than letting them crash the TUI.

## 6. Pending items

- **CV-01..CV-03** (Phase-2 closure cosmetic doc/test-comment items) were
  *not* applied this increment — the increment plan says "applied
  opportunistically" and no natural touch-point arose in these 3 files. They
  remain open for a later increment that edits the relevant `.dev-flow/` docs
  or TC-row comments. Surfaced here so they are not lost.
- `change_list_factory` is deliberately the **resolved scalar/array/string arm
  only**. The adversarial-float and unresolved-entry arms are deferred to the
  increments that first need them (5 / 8), per the plan's scope-creep
  mitigation. The factory currently lives in `tests/test_cdfx_changelist.py`;
  increment 8 is specified to grow it in `tests/conftest.py` — a future
  increment may need to relocate it.

## 7. Suggested next task

**Increment 2 — A2L parameter resolution.** Create `s19_app/tui/cdfx/resolve.py`
with `resolve_against_a2l(...)`, resolving each `ChangeListEntry` against the
*enriched* A2L payload (`enrich_a2l_tags_with_values`, not bare
`extract_a2l_tags` — constraint C-1) and writing `RESOLVED` /
`UNRESOLVED` / `INDEX_OUT_OF_RANGE` / `UNRESOLVED_NO_A2L` onto each entry's
`status`; plus `tests/test_cdfx_resolve.py` (TC-004..TC-007) with the
`make_patch_a2l` synthetic-A2L generator. 2 files.

---

**Stop boundary reached.** Increment 1 is complete: the new test module is
green, the full suite is 435 passed / 0 failed (419 baseline + 16), and
`s19tui` imports unchanged with no UI wiring. Awaiting approval before
starting increment 2.
