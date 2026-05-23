# Increment 003 — Type-driven value display — Review Packet

> **Batch:** 2026-05-21-batch-03 · **Phase 3 (Implementation), Increment 3 of 9.**
> **Branch:** `dev-flow/batch-02-direction-b-restyle`.
> Spec: [`increment-plan.md` §4 — Increment 3](./increment-plan.md) · Requirements:
> [`01-requirements.md`](../01-requirements.md) LLR-003.1, LLR-003.2 (display
> arm of LLR-003.3); Phase-2 review findings A-02, A-03, Q-10.

---

## 1. What changed

Created `s19_app/tui/cdfx/display.py` — the type-driven value-display layer.
The public entry point is `format_value(entry, resolved_type)`: it derives the
Patch Editor's display text for one `ChangeListEntry` from the entry's resolved
A2L type, **without ever mutating the stored physical value**.

Selection follows the `(char_type, datatype)` pair, in the LLR-003.1 order:

1. A `None` value short-circuits to the empty string ("nothing entered yet").
2. An unresolved entry (`resolved_type is None`) falls back to plain decimal
   text (LLR-003.2).
3. `char_type == "ASCII"` selects the quoted-string form — checked **before**
   any `datatype` test, because A2L `ASCII` is a characteristic-kind token and
   there is no `ASCII` `datatype` (Phase-2 finding A-02).
4. Otherwise the `datatype` token selects the numeric form: unsigned integer
   (`UBYTE`/`UWORD`/`ULONG`/`A_UINT64`) → decimal **plus an integral-only hex
   companion**; signed integer (`SBYTE`/`SWORD`/`SLONG`/`A_INT64`) → signed
   decimal; IEEE float (`FLOAT16_IEEE`/`FLOAT32_IEEE`/`FLOAT64_IEEE`) →
   fractional decimal.
5. A resolved entry with an unrecognized / `None` `datatype` falls back to
   plain decimal — the same safe path as the unresolved case (LLR-003.2).

**A-03 — integral-only hex companion.** The hexadecimal companion is shown for
an unsigned-integer parameter **only when the physical value is integral**. The
change-list stores the *physical* value (LLR-003.3); a non-IDENTICAL
`COMPU_METHOD` produces a fractional physical value where `hex()` has no
meaning, so such a value renders decimal-only. The `_hex_companion` helper
returns `None` for a fractional `float`, which suppresses the companion.

**Q-10 — large-`A_UINT64` exactness.** Integer values are kept as Python `int`
end-to-end — `hex()` is applied directly to the `int`, never via a binary64
`float` — so an `A_UINT64` above `2**53` (e.g. `2**64 - 1`) renders its exact
decimal and hexadecimal text with no low-bit loss. A `float` that is integral
(`is_integer()`) is converted with `int()` (exact, no fractional part) before
`hex()`.

`format_value` takes the `ResolvedType` (or `None`) **explicitly** rather than
reading a field off the entry: the increment-1 model has no resolved-type slot,
and the increment-2 `ResolutionResult.type_for(entry)` is the documented
lookup that supplies it. This matches the increment-2 review packet's
"Suggested next task" note and the increment plan's increment-3 signature
guidance. The function is pure — no XML, no Textual, no file I/O.

`cdfx/__init__.py`, `changelist.py`, `resolve.py`, `a2l.py` are **byte-
unchanged**; the increment plan schedules the `__init__.py` re-export extension
for increment 7. `pyproject.toml` / `requirements.txt` are byte-unchanged — no
new dependency.

## 2. Files modified

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/cdfx/display.py` | new | `format_value(entry, resolved_type)` + private helpers `_format_unsigned`, `_hex_companion`, `_format_signed`, `_format_float`, `_plain_decimal`; the `UNSIGNED_INT_DATATYPES` / `SIGNED_INT_DATATYPES` / `IEEE_FLOAT_DATATYPES` token sets. Type-driven value display (LLR-003.1, LLR-003.2). |
| `tests/test_cdfx_display.py` | new | TC-008 (10 tests, incl. the `FLOAT16_IEEE` and large-`A_UINT64` Q-10 boundary cases), TC-009 (4 tests), the TC-010 display arm (3 tests) — 17 tests; plus the local `_entry` fixture helper. |

2 files — within the ≤5 cap and matching the increment-3 spec exactly.

## 3. How to test

Run from the repo root `C:\Users\jjgh8\Github\s19_app`:

```
python -m pytest -q tests/test_cdfx_display.py     # the new module
python -m pytest -q                                # full suite, no regression
python -c "import s19_app.tui.cdfx"                 # cdfx package imports
python -c "import s19_app.tui.cdfx.display"         # display module imports
python -m py_compile s19_app/tui/cdfx/display.py tests/test_cdfx_display.py
```

`ruff` is **not installed** in this environment — `python -m py_compile` was
substituted as the static check on the two new files, as instructed.

## 4. Test results

Actual captured output:

- **`pytest -q tests/test_cdfx_display.py`** → `17 passed in 0.07s`.
- **`pytest -q` (full suite)** → `466 passed, 2 skipped, 3 xfailed in 174.38s`,
  `27 snapshots passed`, **0 failed**. Baseline was 449 passed / 2 skipped /
  3 xfailed; 449 + 17 new = 466 — exact, no regression.
- **`python -c "import s19_app.tui.cdfx"`** → `IMPORT_CDFX_OK` (clean exit).
- **`python -c "import s19_app.tui.cdfx.display"`** → `IMPORT_DISPLAY_OK`.
- **`python -m py_compile` on the 2 new files** → `PY_COMPILE_OK` (clean exit).

The 17 new tests by TC:

- **TC-008** (type-driven display-format selection, LLR-003.1) — 10 tests:
  unsigned integral `UBYTE` 23 → `23 / 0x17`; unsigned **fractional** value
  (non-IDENTICAL `COMPU_METHOD`) → decimal only, no `0x` companion (finding
  A-03); **large `A_UINT64` = `2**64-1`** → exact `18446744073709551615 /
  0xffffffffffffffff` (finding Q-10 — value never routed through `float`);
  negative `SWORD` → `-1234`, no companion; positive `SLONG` → `77`, no
  companion; `FLOAT32_IEEE` → `12.5`; **`FLOAT16_IEEE`** → `0.5` (Q-10 float
  boundary); integral `FLOAT64_IEEE` → `3.0` (keeps the `.0` tail); `ASCII`
  `char_type` → `"REV_C"`; `ASCII` branch wins over a recognized `datatype`
  token (A-02 selection order).
- **TC-009** (display-format fallback for unresolved entries, LLR-003.2) — 4
  tests: unresolved entry → plain decimal `42`, no type-driven hex; unresolved
  float → `3.14`, no exception; resolved-but-unknown `datatype` (`None` /
  `"WEIRD"`) → plain decimal fallback; `None` value → empty string, no crash.
- **TC-010** (physical value stored, display derived — display arm, LLR-003.3)
  — 3 tests: formatting through several type branches leaves `entry.value`
  the untouched physical `int`; the hex companion is a derived display
  artifact, the stored value stays `255` (not `"0xff"`); an ASCII value is
  stored unquoted (`REV_C`), the quotes belong to the rendered text only.

## 5. Risks

- **`format_value` consumes the increment-2 `ResolutionResult` contract.**
  The function signature is `format_value(entry, resolved_type)` —
  `resolved_type` is whatever `ResolutionResult.type_for(entry)` returns
  (`ResolvedType` or `None`). Increment 7's Patch Editor must thread the
  `ResolutionResult` to the renderer and call `type_for` per row; it must not
  expect a resolved-type field on the entry (there is none). If a later
  increment adds a `resolved` slot to the model, this signature would be
  revisited — flagged so the choice stays explicit, consistent with the
  increment-2 packet's matching risk note.
- **The hex companion gates on the *Python value type*, not on the
  `COMPU_METHOD`.** `_hex_companion` shows `0x...` when the stored value is an
  `int` or an integral `float`. The requirement frames the integral condition
  as "effectively IDENTICAL-conversion parameters" (A-03), but `display.py`
  has no `COMPU_METHOD` — it has only the stored physical value. The
  value-type test is the faithful, observable proxy: a non-IDENTICAL
  conversion that yields a fractional physical value is stored as a fractional
  `float` and correctly gets no companion; a non-IDENTICAL conversion that
  *happens* to yield a whole number would get a companion. This is acceptable
  — the companion of an integral value is always well-defined — but it is a
  value-driven, not conversion-driven, decision and is recorded as such.
- **Boolean values render via the integer path.** `_hex_companion` treats
  `bool` (an `int` subclass) as the integer it is, so a `True` stored against
  a `VALUE`/`BOOLEAN` characteristic resolved as an unsigned type would render
  `True / 0x1`. The editable `BOOLEAN` category (LLR-004.2, finding A-04) is a
  writer concern of increment 4; the change-list `PhysicalValue` union is
  `int | float | str | None` (no explicit `bool`), so in practice boolean-like
  values arrive as `0` / `1` `int`s. No defect, but noted so increment 4/7 can
  decide whether a `BOOLEAN` parameter wants a distinct display arm (the
  research §6 "enum label if a `COMPU_VTAB` resolves" line is out of this
  increment's LLR scope).
- **Float display uses Python `str(float)`.** `_format_float` renders via
  `str(float(value))` — Python's shortest round-trip-faithful repr. This is a
  *display* string, intentionally distinct from the writer's `repr()`-based
  *serialization* (LLR-004.8, increment 4). The two are not required to be
  byte-identical: one is for the engineer's eye, the other for the `.cdfx`
  `V` element. Recorded so increment 4 does not assume display text and `V`
  text are the same function.
- **`A_UINT64` exactness depends on the value never being a `float`
  upstream.** `display.py` keeps integers as `int`, but it cannot guarantee
  the *resolver* or a future *reader* hands it an `int` rather than a `float`.
  TC-008's large-`A_UINT64` test pins the display side; the read side
  (`R-VALUE-NOT-NUMERIC` decode) is increment 5's responsibility — if the
  reader were to decode a huge `V` through `float`, exactness would be lost
  before `format_value` ever sees the value. Out of this increment's scope,
  flagged for increment 5.

## 6. Pending items

- **`cdfx/__init__.py` re-export of `format_value`** is deferred to increment
  7, per the increment plan (the `__init__.py` extension is listed under
  increment 7's file set). This increment's tests import from
  `s19_app.tui.cdfx.display` directly, keeping the increment at exactly the
  2 spec'd files.
- **`CV-01..CV-03`** (Phase-2 closure cosmetic doc / test-comment items) —
  carried over from increments 1–2; still open. No natural touch-point arose
  in these 2 new files. Surfaced again so they are not lost.
- **The TC-010 storage arm** was completed in increment 1
  (`tests/test_cdfx_changelist.py`); this increment adds the **display arm**
  (rendering does not mutate the stored value). LLR-003.3 is now fully
  covered across increments 1 and 3, as the increment plan staged it.
- **`BOOLEAN`-category and `COMPU_VTAB` enum-label display** (research §6 row
  5) is **not** an LLR-003.1/003.2 obligation and is **not** implemented —
  LLR-003.1 enumerates only the unsigned / signed / float / ASCII forms. No
  scope creep taken; noted in case a later increment wants it.

## 7. Suggested next task

**Increment 4 — CDFX writer + `W-*` validator.** Create
`s19_app/tui/cdfx/writer.py` (`write_cdfx` building the `MSRSW` backbone, one
`SW-INSTANCE` per resolved entry, `V`/`VG`/`VT` encoding, the leading
`Created with s19_app CDF 2.0 Writer` comment, `repr()`-precision float text,
and the standalone `validate_w_rules(tree)` `W-*` validator),
`tests/test_cdfx_writer.py` and `tests/test_cdfx_w_rules.py`. 14 TCs
(TC-011..TC-014, TC-019a..h, TC-032, TC-033 writer arm), 3 files. Note: the
writer gates on entry `status` (excludes `UNRESOLVED` *and*
`INDEX_OUT_OF_RANGE` per LLR-004.5) — not on "is there a resolved type", since
`type_for` returns a type for out-of-range entries too (increment-2 risk note).

---

**Stop boundary reached.** Increment 3 is complete: the new test module is
green (17 passed), the full suite is 466 passed / 0 failed (449 baseline + 17),
`s19_app.tui.cdfx` imports unchanged, and no UI behavior changed. Awaiting
approval before starting increment 4.
