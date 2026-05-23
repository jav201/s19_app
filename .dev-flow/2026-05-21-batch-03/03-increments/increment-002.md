# Increment 002 — A2L parameter resolution — Review Packet

> **Batch:** 2026-05-21-batch-03 · **Phase 3 (Implementation), Increment 2 of 9.**
> **Branch:** `dev-flow/batch-02-direction-b-restyle`.
> Spec: [`increment-plan.md` §4 — Increment 2](./increment-plan.md) · Requirements:
> [`01-requirements.md`](../01-requirements.md) LLR-002.1..002.4, constraint C-1.

---

## 1. What changed

Created `s19_app/tui/cdfx/resolve.py` — the parameter-resolution layer that
matches each `ChangeListEntry` against the **enriched** A2L payload and assigns
a `ResolutionStatus`. The public entry point is `resolve_against_a2l(change_list,
enriched_a2l_tags)`: it stamps every entry's declared `status` field with one of
`RESOLVED` / `UNRESOLVED` / `INDEX_OUT_OF_RANGE` / `UNRESOLVED_NO_A2L`, and
returns a `ResolutionResult` carrying the change-list plus a per-entry map of
resolved A2L type metadata (`ResolvedType` — `char_type` / `datatype` /
`element_count`). Resolution consumes the enriched-tag list produced by
`a2l.enrich_a2l_tags_with_values` (constraint C-1); it never re-parses A2L text
and does not modify `a2l.py`. Pure Python — no XML, no Textual.

**Design note — why a `ResolutionResult` instead of a `resolved` field on the
entry.** The increment-1 `ChangeListEntry` is `@dataclass(slots=True)` with four
declared slots; it has no slot to hold the resolved A2L type. Adding one would
be a model change to `changelist.py` — a third file and a touch outside this
increment's 2-file spec. Since the increment-2 spec lists exactly 2 files
(`resolve.py` + the test), the resolved type is returned **alongside** the
change-list in `ResolutionResult.resolved_types` (keyed by the entry's
`(parameter_name, array_index)` identity), and only the entry's *declared*
`status` field is mutated in place. The model is left byte-unchanged.
`ResolutionResult.type_for(entry)` is the downstream lookup the increment-3
display layer and increment-4 writer will call.

**C-1 / A-01 handled.** A bare `extract_a2l_tags` `CHARACTERISTIC` tag has
`datatype = None`; the decode-relevant fields (`decode_type`, `element_count`,
`char_type`) are populated only after `enrich_a2l_tags_with_values`. The
resolver therefore reads `decode_type` (not the bare `datatype`) for the
`ResolvedType.datatype` field, and the synthetic A2L fixture is built with
`RECORD_LAYOUT`s so enrichment genuinely populates those fields. TC-004's
`test_tc004_resolution_consumes_enriched_not_bare_tags` pins this: it feeds the
resolver bare tags and enriched tags side by side and asserts only the enriched
run yields a data type — a regression to bare-tag resolution fails the test.

No runtime dependency was added; `pyproject.toml` / `requirements.txt` are
byte-unchanged. `cdfx/__init__.py` was **not** extended this increment (tests
import from `s19_app.tui.cdfx.resolve` directly) so the increment stays at
exactly the 2 spec'd files — the increment plan schedules the `__init__.py`
re-export extension for increment 7.

## 2. Files modified

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/cdfx/resolve.py` | new | `resolve_against_a2l` + `ResolutionResult` / `ResolvedType` / private `_resolve_entry`, `_element_count_of`. Resolves entries against the enriched A2L payload (LLR-002.1..002.4). |
| `tests/test_cdfx_resolve.py` | new | TC-004..TC-007 (14 tests) + the `make_patch_a2l` / `enriched_patch_tags` synthetic-A2L helpers. |

2 files — within the ≤5 cap and matching the increment-2 spec exactly.

## 3. How to test

Run from the repo root `C:\Users\jjgh8\Github\s19_app`:

```
python -m pytest -q tests/test_cdfx_resolve.py        # the new module
python -m pytest -q                                   # full suite, no regression
python -c "import s19_app.tui.cdfx"                    # cdfx package imports
python -c "import s19_app.tui.cdfx.resolve"            # resolve module imports
python -m py_compile s19_app/tui/cdfx/resolve.py tests/test_cdfx_resolve.py
```

`ruff` is **not installed** in this environment — `python -m py_compile` was
substituted as the static check on the two new files, as instructed.

## 4. Test results

Actual captured output:

- **`pytest -q tests/test_cdfx_resolve.py`** → `14 passed in 0.11s`.
- **`pytest -q` (full suite)** → `449 passed, 2 skipped, 3 xfailed in 185.44s`,
  `27 snapshots passed`, **0 failed**. Baseline was 435 passed / 2 skipped /
  3 xfailed; 435 + 14 new = 449 — exact, no regression.
- **`python -c "import s19_app.tui.cdfx"`** → `IMPORT_CDFX_OK` (clean exit).
- **`python -c "import s19_app.tui.cdfx.resolve"`** → `IMPORT_RESOLVE_OK`.
- **`python -m py_compile` on the 2 new files** → `PY_COMPILE_OK` (clean exit).

The 14 new tests by TC:
- **TC-004** (resolve a known parameter, LLR-002.1) — 4 tests: scalar resolves
  with `ResolvedType(VALUE, UWORD, 1)`; 1-D array resolves with `element_count`
  3; resolution against bare vs. enriched tags (C-1 / A-01 — only the enriched
  run yields a data type); resolver does not re-parse A2L text (the `.a2l` file
  is deleted before resolving, resolution still succeeds).
- **TC-005** (unresolved-name, LLR-002.2) — 2 tests: an unknown name → `UNRESOLVED`
  with no type and no exception; an unresolved entry leaves a valid sibling
  resolvable and the list usable.
- **TC-006** (array-index range check, LLR-002.3) — 5 tests: index 5 on a
  3-element parameter → `INDEX_OUT_OF_RANGE`; negative index → `INDEX_OUT_OF_RANGE`;
  index 2 (last valid slot) → `RESOLVED`; scalar index 0 → `RESOLVED`; an
  out-of-range entry still carries its resolved type via `type_for`.
- **TC-007** (no loaded A2L, LLR-002.4) — 3 tests: `None` A2L → every entry
  `UNRESOLVED_NO_A2L`, empty type map; an empty tag list is treated as no A2L;
  the change-list and its values stay intact and the result wraps the same list.

## 5. Risks

- **`ResolutionResult` is the type-carry contract — increments 3/4 depend on
  it.** Because the model has no `resolved` field, the resolved A2L type lives
  only in `ResolutionResult.resolved_types` (keyed by `EntryKey`). The
  increment-3 display layer and increment-4 writer must thread the
  `ResolutionResult` through alongside the `ChangeList` rather than reading a
  field off the entry. If a later increment instead chooses to add a `resolved`
  slot to the model, this return shape would be reworked — flagged so the
  decision is explicit, not silent drift.
- **`INDEX_OUT_OF_RANGE` entries are in `resolved_types`.** An out-of-range
  entry resolved its *parameter* (only the index failed), so its `ResolvedType`
  is recorded and `type_for` returns it. Increment 4's writer must gate on the
  entry `status` (exclude `UNRESOLVED` *and* `INDEX_OUT_OF_RANGE` per LLR-004.5)
  — not on "is there a resolved type" — or it would write an out-of-range entry.
- **`char_type` carries the A2L characteristic kind, not a numeric type.** For
  the synthetic fixture `char_type` is `VALUE` / `VAL_BLK` / `ASCII` and
  `datatype` (from `decode_type`) is `UWORD` / `UBYTE`. The increment-3 display
  layer selects the ASCII branch from `char_type` and the numeric branch from
  `datatype` (LLR-003.1, finding A-02). A real A2L `MEASUREMENT` would have
  `char_type = None`; resolution handles that (`ResolvedType.char_type` is
  `str | None`) but the editable scope is characteristics (assumption A-3).
- **Element-count fallback to 1.** `_element_count_of` returns 1 for a tag with
  a missing or non-numeric `element_count`. A characteristic whose record
  layout did not resolve would therefore be treated as a scalar — index 0
  resolves, index ≥1 is flagged out-of-range. This is the safe default (it
  never over-permits an index) but a malformed A2L array could be mis-sized;
  the A2L-side enrichment is out of this increment's scope (no `a2l.py` change).
- **Name match is exact and case-sensitive.** `resolve_against_a2l` matches
  `parameter_name` verbatim against enriched-tag `name`. A2L names are
  case-sensitive identifiers, so this is correct, but an engineer's typo or
  case mismatch yields `UNRESOLVED` — surfaced as a status, never a crash
  (LLR-002.2), and the increment-7 UI will show it.

## 6. Pending items

- **`cdfx/__init__.py` re-export of the resolution surface is deferred to
  increment 7**, per the increment plan (the `__init__.py` extension is listed
  under increment 7's file set). This increment's tests import from
  `s19_app.tui.cdfx.resolve` directly, keeping the increment at exactly the
  2 spec'd files. If an earlier increment needs `resolve_against_a2l` on the
  package's public surface, the one-line additive re-export can be added then.
- **CV-01..CV-03** (Phase-2 closure cosmetic doc/test-comment items) — carried
  over from increment 1; still open, no natural touch-point arose in these 2
  files. Surfaced again so they are not lost.
- **`make_patch_a2l` lives in `tests/test_cdfx_resolve.py`.** §5.4 of the
  requirements specifies the synthetic fixtures eventually live in
  `tests/conftest.py`. Like `change_list_factory` in increment 1, `make_patch_a2l`
  is kept local to its first-consuming test module for now; relocation to
  `conftest.py` is a future increment's call when a second module needs it
  (TC-029 / TC-030 cross-check tests in increment 5).

## 7. Suggested next task

**Increment 3 — Type-driven value display.** Create `s19_app/tui/cdfx/display.py`
with `format_value(...)`: select the display form from `(char_type, datatype)`
of the resolved parameter — `ASCII` `char_type` → quoted string; unsigned int →
decimal + hex companion **only when the physical value is integral** (finding
A-03); signed int → signed decimal; IEEE float → fractional decimal; unresolved
entry → plain decimal (LLR-003.2). Plus `tests/test_cdfx_display.py` (TC-008,
TC-009, the TC-010 display arm). 2 files. Note: `format_value` will need the
resolved type — it reads it from the increment-2 `ResolutionResult` (the
`type_for` lookup), so the increment-3 signature should accept that, not a
non-existent entry field.

---

**Stop boundary reached.** Increment 2 is complete: the new test module is
green (14 passed), the full suite is 449 passed / 0 failed (435 baseline + 14),
`s19_app.tui.cdfx` imports unchanged, and no UI behavior changed. Awaiting
approval before starting increment 3.
