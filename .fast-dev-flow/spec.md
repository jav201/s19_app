# fast-dev-flow spec — A2L CHARACTERISTIC length from resolved RECORD_LAYOUT (P-1)

- **Date:** 2026-07-18
- **Batch:** a2l-record-layout-length (backlog P-1, follow-up to the a2l-missing-length-fix)
- **Flow:** /fast-dev-flow
- **Language:** English
- **Run mode / merge:** Autonomous through self-merge (operator-authorized this batch; per-batch, not carried). Surface any HIGH finding / unexpected fallout before merge.
- **Status:** Phase A — spec

---

## 1. Objective

Populate a scalar `CHARACTERISTIC`'s byte `length` by **resolving its RECORD_LAYOUT**, so records
that reference a project-named layout (e.g. `RL_U8`, whose *name* encodes no size) become
memory-checkable instead of landing `length=None` → grey "not checked". This is the deeper root the
a2l-missing-length-fix (🅰) flagged: `_infer_length_characteristic` hunted a non-standard `LENGTH`
keyword and `sizeof_from_deposit(name)`, never resolving the actual layout definition.

## 2. Root cause (grounded)

`_infer_length_characteristic` (`a2l.py:707`) derives the element size only via
`sizeof_from_deposit(deposit)`, which pattern-matches size-encoded *names* (`__UBYTE_Z` → 1) or a
datatype keyword. A project layout named `RL_U8` matches neither → `el=None` → `length=None`. Yet the
layout **is** defined (`/begin RECORD_LAYOUT RL_U8  FNC_VALUES 1 UBYTE …`), and the sibling helper
`_resolve_record_layout(name, record_layouts_by_name)` already resolves it to `decode_type=UBYTE`
(size 1) — but only for decode metadata (`a2l.py:1164`), never wired into `length`.

Confirmed on `examples/case_01_basic_valid/firmware.a2l`: `CAL_BLOCK_A`/`CAL_BLOCK_B`
(`VALUE 0x… RL_U8 …`) resolve to `byte_size=1` via `_resolve_record_layout` but parsed with
`length=None` before this fix.

## 3. The fix

Thread `record_layouts_by_name` into `_infer_length_characteristic`; when `sizeof_from_deposit`
yields nothing **and** the object is a scalar `VALUE`, resolve the layout and take its element
datatype size:

```python
el = sizeof_from_deposit(deposit)
if el is None and char_type == "VALUE" and record_layouts_by_name:
    meta = _resolve_record_layout(deposit, record_layouts_by_name)
    if meta and meta.get("decode_type"):
        el = DATATYPE_SIZES.get(meta["decode_type"])
```

The existing MATRIX_DIM / VAL_BLK / return-`el` logic is unchanged and runs after.

**Conservative `VALUE`-only scope — a correctness decision, not laziness.** The byte-range memory
check (`_memory_range_in_map(addr, length, mem_map)`) trusts `length`. A CURVE/MAP is an array over
its axes, so the element datatype size UNDER-reports the true span → the check would falsely pass on
too few bytes (false-green). Deriving those correctly needs axis/MATRIX_DIM resolution (a larger
feature). So CURVE/MAP/VAL_BLK stay `length=None` (honest grey) unless already sized by a MATRIX_DIM
or a name-encoded deposit. Scalar `VALUE` is safe because element size == total size.

`a2l.py` is already UNFROZEN (🅰) — **no engine-unfreeze increment needed** this batch.

## 4. Acceptance criteria (observable)

- **AC-1** — When a scalar `VALUE` CHARACTERISTIC references a RECORD_LAYOUT whose name encodes no
  size (`RL_U8`) but whose definition is `FNC_VALUES 1 UBYTE …`, the parsed tag shall have
  `length == 1` (the datatype size), not `None`.
- **AC-2** — With that length and the address present in the loaded image, the tag shall be
  memory-checked: `schema_ok=True`, `memory_checked=True`, `in_memory` reflecting coverage (no longer
  grey/`memory_checked=False`).
- **AC-3** (no false-green) — A `CURVE` or `MAP` CHARACTERISTIC referencing a name-only RECORD_LAYOUT
  shall keep `length == None` (not the element size), so the memory check does not pass on an
  under-counted span.
- **AC-4** — A CHARACTERISTIC whose deposit name already encodes a size (`__UWORD_Z`) or whose layout
  is absent from `record_layouts_by_name` shall be unchanged (2 / `None` respectively) — the fallback
  is additive.
- **AC-5** — Full gate `pytest -q -m "not slow"` stays green (0 failures); no frozen engine test file
  is modified.

## 5. Security flags

Scanned objective + criteria + description. No auth/secrets/external/PII/destructive-DB/network
patterns. `security_required: **false**`. The change lives in an existing parser of untrusted A2L;
it derives a length from already-parsed layout tokens (ints), adds no input surface, and *tightens*
coverage honesty (refuses to guess CURVE/MAP spans).

## 6. Files (blast radius)

**Increment 1 — fix + tests (3 files):**
1. `s19_app/tui/a2l.py` — thread `record_layouts_by_name`, VALUE-only layout-size fallback.
2. `tests/test_a2l_record_layout_length.py` — **NEW** AC-1..AC-4 unit/behavioral proofs.
3. `REQUIREMENTS.md` — note layout-derived length under the A2L parsing/colour rows.

**Frozen, preserved unchanged:** `test_tui_a2l.py`, `test_validation_a2l.py`, all `_ENGINE_TEST_FILES`.
(Measured: a2l/validation/directionb/supplemental/missing-length suites = 210 passed with the fix.)

## 7. Pending / deferred

- **P-1b** CURVE/MAP/axis length derivation (needs AXIS_DESCR + MATRIX_DIM resolution) — the honest
  next step for array types; deliberately out of scope to avoid false-green.
- **P-2** (unchanged) re-freeze `a2l.py` against a post-fix baseline — should come AFTER P-1 so we do
  not re-freeze then re-edit.

## 8. Batch status

| Current phase | Phase A — spec written |
