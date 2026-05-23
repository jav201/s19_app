# Increment 010 — Round-trip + adversarial-float hardening + the S8-2 fix

> **Phase 3 · batch-03 · Increment 10.** Implements **TC-024** — the end-to-end
> CDFX write→read structural-equality verdict, including the three adversarial
> IEEE binary64 floats and the coalesce→expand `Optional[int]` key shape — and
> applies the **S8-2** security finding from increment 8: a pre-read
> `stat().st_size` cap in `reader._resolve_source` so an over-cap `.cdfx` file
> is rejected before it is read into memory. Spec: increment-plan §A.4 —
> Increment 10; requirements TC-024, LLR-004.8 / LLR-004.9 / LLR-005.1 /
> LLR-005.6 (round-trip verdict), LLR-006.8 (on-disk size cap). Branch:
> `dev-flow/batch-02-direction-b-restyle`.

## 1. What changed

The shared `change_list_factory` helper was **relocated** from
`tests/test_cdfx_changelist.py` to `tests/conftest.py` (a relocation
increment 5 explicitly deferred to this increment) and **extended** with an
adversarial-float arm: a `FLOAT_ADV_BLOCK` 1-D array carrying the three IEEE
binary64 values `0.1`, the denormal `5e-324` and a 17-significant-digit value
(`8.98846567431158e307`), exposed as the module-level `ADVERSARIAL_FLOATS`
tuple. A companion `change_list_resolution` helper was added so a write test
can build the `ResolutionResult` the writer needs without running the A2L
pipeline. `test_cdfx_changelist.py` now imports the factory from `conftest.py`
instead of defining it locally.

The new `tests/test_cdfx_roundtrip.py` implements **TC-024**: it builds the
factory change-list (a `None`-index scalar, a `None`-index ASCII string, an
integer-indexed 1-D integer array, and the integer-indexed adversarial-float
array), serializes it with `write_cdfx`, parses the bytes back with
`read_cdfx`, and asserts structural equality — the same
`(parameter_name, array_index)` key set including the `Optional[int]` shape
(scalar/string → `array_index is None`, an *N*-array → exactly `(name, 0)…
(name, N-1)`), the same per-key values with **exact `==` and no float
tolerance**, and the same entry order. The three adversarial floats are the
non-tautology guard: a denormal collapses to `0.0` and a 17-digit value loses
its tail under any lossy `str()` / `%g` / fixed-width writer, so the test
genuinely fails if the writer ever drops full `repr()` precision (LLR-004.8).
The integer and float arrays exercise the coalesce-on-write (LLR-004.9) →
expand-on-read (LLR-005.6) path end-to-end.

**The S8-2 fix.** Increment 8's review packet §5 flagged that the reader's
256 MB cap measured the *in-memory* byte length: for a path source the bytes
were read in full via `Path.read_bytes` and only then rejected, so a truly
oversized file would be loaded into memory before the length check fired
(LLR-006.8 wants the *on-disk* size checked before the read). The fix is a
**pre-read `stat().st_size` guard** in `reader._resolve_source`: after
`resolve_input_path` resolves a path source, the file's on-disk
`stat().st_size` is checked against `MAX_CDFX_SIZE_BYTES` **before**
`Path.read_bytes` — an over-cap file is rejected as one `R-XML-PARSE`
`ValidationIssue` and `read_bytes` is never called. This mirrors
`workspace.copy_into_workarea`'s `stat().st_size`-before-copy pattern. A
failed `stat()` (`OSError`) is itself converted to one `R-XML-PARSE` issue
rather than escaping. The fix is a pre-read guard only — no other reader
behavior changed: a `bytes` source still skips path resolution and is still
size-checked by the existing in-memory `_probe_size` seam; a within-cap path
is read and parsed exactly as before; the in-memory `_probe_size` check in
`read_cdfx` is left in place (it still covers the `bytes` source, which has no
on-disk size, so a path source is now size-checked twice — once on disk
before the read, once in memory after).

The increment-8 `tests/test_cdfx_safety.py` size-cap test (TC-035) was
extended with two tests asserting the file is **not** read when over-cap (a
`read_bytes` spy against a real sparse over-cap file) and that a within-cap
path **is** read (the spy is meaningful — the guard gates, it does not block
every read).

`s19_app/tui/cdfx/writer.py`, `changelist.py`, `resolve.py`, `display.py`,
`app.py`, `workspace.py`, `pyproject.toml` / `requirements.txt` are
**byte-unchanged** — no new dependency, stdlib only (C-2).

## 2. Files modified

| File | Status | Purpose |
|------|--------|---------|
| `tests/conftest.py` | **modified** | Relocated `change_list_factory` here from `test_cdfx_changelist.py` and extended it with the `FLOAT_ADV_BLOCK` adversarial-float array; added the module-level `ADVERSARIAL_FLOATS` tuple and the `change_list_resolution` helper (builds the matching `ResolutionResult` for a write test). Added a `TYPE_CHECKING` import block for the `ChangeList` / `ResolutionResult` annotations. |
| `tests/test_cdfx_roundtrip.py` | **new** | TC-024 — 8 tests: key-set recovery, `Optional[int]` index-shape preservation, scalar/string value recovery, integer-array value recovery, exact-`==` adversarial-float recovery, full structural equality, entry-order preservation, and the via-path round-trip. |
| `s19_app/tui/cdfx/reader.py` | **modified** | S8-2 fix: `_resolve_source` now checks the resolved path's on-disk `stat().st_size` against `MAX_CDFX_SIZE_BYTES` **before** `Path.read_bytes`, rejecting an over-cap file (or an un-`stat`-able path) as one `R-XML-PARSE` issue with no file read into memory. `_resolve_source` docstring + the module-docstring safety bullet updated. No other reader behavior changed. |
| `tests/test_cdfx_safety.py` | **modified** | Extended TC-035 with two S8-2 tests: an over-cap (sparse) `.cdfx` path is rejected by the on-disk guard with a `read_bytes` spy proving the file was never read; a within-cap path **is** read (the guard does not over-reject). |
| `tests/test_cdfx_changelist.py` | **modified** | Removed the local `change_list_factory` definition (relocated to `conftest.py`); now imports it from `tests.conftest`. Module docstring updated to record the relocation. |

5 files — at the ≤5 cap. The 5th file (`test_cdfx_changelist.py`) is the
consequence of the `change_list_factory` **relocation**, which increment 5's
review packet §6 and increment-plan §A.4 explicitly deferred to increment 10;
it is in-scope, not scope creep.

## 3. How to test

Run from the repo root `C:\Users\jjgh8\Github\s19_app`:

```
python -m pytest -q tests/test_cdfx_roundtrip.py tests/test_cdfx_safety.py
python -m pytest -q                                   # full suite, no regression
python -c "import s19_app.tui.cdfx"                    # cdfx package imports
python -m py_compile s19_app/tui/cdfx/reader.py tests/conftest.py tests/test_cdfx_roundtrip.py tests/test_cdfx_safety.py tests/test_cdfx_changelist.py
```

`ruff` is **not installed** in this environment — `python -m py_compile` was
substituted as the static check on the five files, as instructed.

## 4. Test results

Actual captured output:

- **`pytest -q tests/test_cdfx_roundtrip.py tests/test_cdfx_safety.py`** →
  `21 passed in 0.35s` — 8 round-trip tests + 13 safety tests (11 increment-8
  + 2 new S8-2).
- **`pytest -q` (full suite)** → `601 passed, 2 skipped, 3 xfailed in 176.37s`,
  `27 snapshots passed`, **0 failed**. Baseline was 591 passed / 2 skipped /
  3 xfailed; 591 + 10 new (8 round-trip + 2 S8-2) = 601 — exact, no
  regression, skip/xfail counts unchanged.
- **`python -c "import s19_app.tui.cdfx"`** → `IMPORT_CDFX_OK ['ChangeList',
  'ChangeListEntry', 'ResolutionStatus', 'read_cdfx', 'validate_w_rules',
  'write_cdfx', 'write_cdfx_to_workarea']` (clean exit) — `__init__` is
  byte-unchanged, no re-export added.
- **`python -m py_compile`** on the five files → `PY_COMPILE_ALL_OK`.
- **`pytest -q tests/test_cdfx_changelist.py`** (factory-relocation regression
  check) → all `test_cdfx_changelist.py` tests pass against the imported
  factory — TC-001/002/003/010 are unaffected by the relocation and the added
  `FLOAT_ADV_BLOCK` group (TC-003 asserts iteration stability, not the exact
  key set).

### New tests by TC

**`tests/test_cdfx_roundtrip.py` (8 tests — TC-024):**
- `test_tc024_round_trip_recovers_the_entry_key_set` — the recovered
  `(parameter_name, array_index)` key set equals the original's.
- `test_tc024_round_trip_preserves_optional_int_index_shape` — scalar/string
  entries recover `array_index is None`; each array recovers exactly the
  contiguous integers `[0, 1, 2]` — pins the shape, not just the count.
- `test_tc024_round_trip_preserves_scalar_and_string_values` — the scalar
  integer `23` and the ASCII string `"REV_C"` survive exactly.
- `test_tc024_round_trip_preserves_integer_array_values` — the 1-D integer
  array's three elements round-trip to `23/24/25` in positional order.
- `test_tc024_round_trip_preserves_adversarial_floats_exactly` — the three
  adversarial IEEE floats round-trip with exact `==` (no tolerance); the
  denormal is asserted not to have collapsed to `0.0`.
- `test_tc024_round_trip_is_structurally_equal` — the full key→value map of
  the recovered change-list equals the original's.
- `test_tc024_round_trip_preserves_entry_order` — the recovered entry order
  matches the original (LLR-001.4).
- `test_tc024_round_trip_via_path` — the round-trip holds when the `.cdfx` is
  written to a `tmp_path` file and re-read from a resolved path.

**`tests/test_cdfx_safety.py` (2 new tests — TC-035 / S8-2):**
- `test_tc035_oversized_path_not_read_into_memory` — a real **sparse**
  over-cap `.cdfx` file (created with `truncate` so it reports an over-cap
  `st_size` without 256 MB of real bytes) is rejected as one `R-XML-PARSE`
  issue; a `Path.read_bytes` spy proves the file content was **never read
  into memory** — the on-disk `stat()` guard rejected it first.
- `test_tc035_under_cap_path_is_read` — a within-cap `.cdfx` path **is**
  read (the spy records the read) and parses to one entry — the guard gates,
  it does not over-reject.

No code defect was found during the run — the reader change and all three
test files passed on the first full-suite run after implementation.

## 5. Risks

- **TC-024 non-tautology — verified by construction.** The increment plan
  (Q-03) flagged that a round-trip test with "nice" float fixtures is
  tautological. The three fixtures are adversarial: `0.1` has no short exact
  decimal, `5e-324` is the smallest positive binary64 denormal (a fixed-width
  format truncates it to `0.0`), and `8.98846567431158e307` carries 17
  significant digits (`%g` drops the tail). The test asserts exact `==` on
  each and additionally asserts the denormal did not collapse to `0.0` — a
  lossy writer fails at least one assertion. The writer's `repr()`-precision
  emission (LLR-004.8, shipped increment 4) is what makes the test pass.
- **The S8-2 fix is a pre-read guard only.** No other reader behavior changed:
  a `bytes` source still skips path resolution; a within-cap path is read and
  parsed exactly as before; the in-memory `_probe_size` check in `read_cdfx`
  is retained (it is the only size check for a `bytes` source). A path source
  is now size-checked twice — on disk before the read, in memory after — and
  the on-disk check is the one that keeps an over-cap file out of memory. This
  double-check is intentional and is documented in the `_resolve_source`
  docstring `Notes` section; it is not a defect.
- **`stat()` is a TOCTOU window.** Between `_resolve_source`'s `stat()` and
  `read_bytes` the file could in principle grow past the cap. This is the
  same TOCTOU window `workspace.copy_into_workarea` accepts for its own
  `stat()`-before-copy guard — the fix matches the established app pattern
  rather than inventing a stricter one (engineering rule 11). A `.cdfx`
  arriving from a calibration workflow is not an adversarially-mutating file;
  the in-memory `_probe_size` check still runs after the read as a second
  bound. Recorded, not speculatively hardened (engineering rule 2).
- **`change_list_factory` relocation perturbs a shared fixture file.** The
  factory moved into `conftest.py` and `test_cdfx_changelist.py` now imports
  it. The full suite is the cross-check: 601 passed, no regression in any
  module. The added `FLOAT_ADV_BLOCK` group is purely additive — TC-003
  asserts iteration stability and insertion order, not the exact key set, so
  the extra group is harmless to the existing changelist tests.
- **The sparse-file fixture depends on filesystem sparse support.** The S8-2
  over-cap test uses `truncate` to a logical over-cap size. NTFS (this
  Windows machine) and modern Linux filesystems all support sparse files, so
  `truncate` does not write 256 MB of real bytes. On an exotic filesystem
  without sparse support the test would briefly allocate a 256 MB file; this
  is the standard pattern and matches the environment. The test asserts
  `st_size == over_cap` up front, so a fixture that did not actually reach
  over-cap fails loudly rather than silently passing.
- **The increment-5 stale-test note is now closed.** Increment 6 rewrote the
  writer's scalar tests to `array_index=None`; this increment's factory
  carries the final `Optional[int]` shape. No stale `array_index=0` scalar
  remains in the touched files.

## 6. Pending items

- **Increment 11 — integration save/load + containment UI tests.** TC-024 is
  the function-level round-trip; the screen-level save→file-appears /
  load→rows-populate integration arm (TC-026 depth) and the containment /
  dedup / reparse-point UI tests (TC-036) through `App.run_test()` are
  increment 11.
- **CV-01** — the Phase-2 closure cosmetic doc item still has no natural
  touch-point in this increment's five files; surfaced again so it is not
  lost (it is a documentation-only item, deferrable to any later increment
  that edits the relevant file).
- **No security-reviewer pass is required for this increment specifically.**
  The S8-2 fix is a hardening of the increment-8 size cap, and increment 8
  already carries the standing security-reviewer request. The S8-2 change
  should be folded into that same review (it is a `stat()`-before-read guard,
  no new I/O surface, no new dependency) — flagged here for the
  `security-reviewer` so the increment-8 review covers the final form of the
  size cap.

## 7. Suggested next task

**Increment 11 — Integration save/load + containment UI tests.** Drive the
Patch Editor save action (a `.cdfx` appears under `.s19tool/workarea/`,
including a `VAL_BLK` file loading back as the per-element rows) and the
work-area containment / dedup / reparse-point rejection through
`App.run_test()` + `pilot`: `tests/test_tui_patch_editor.py` (modified) for
the save/load integration depth and the TC-027a Patch-Editor-load arm,
`tests/test_tui_patch_containment.py` (new) for TC-036 with a privilege-gated
reparse-point arm (CV-03). 2–3 files, 3 TCs. Use `tmp_path` as the app base
dir (the established harness pattern). If increment 11 surfaces a real UI
defect whose fix would push past the file count, **stop and request
approval**.

---

**Stop boundary reached.** Increment 10 is complete: `tests/conftest.py`
hosts the relocated, adversarial-float-extended `change_list_factory` plus the
`ADVERSARIAL_FLOATS` tuple and `change_list_resolution` helper;
`tests/test_cdfx_roundtrip.py` implements TC-024 — the write→read structural-
equality verdict with exact-`==` adversarial floats and the coalesce→expand
`Optional[int]` key shape; `reader._resolve_source` applies the S8-2 fix — a
pre-read `stat().st_size` cap so an over-cap `.cdfx` is rejected before any
file content is read into memory; `tests/test_cdfx_safety.py` pins that with a
`read_bytes` spy; `tests/test_cdfx_changelist.py` imports the relocated
factory. The targeted modules are green (21 passed); the full suite is
601 passed / 2 skipped / 3 xfailed / 0 failed (591 baseline + 10);
`s19_app.tui.cdfx` imports unchanged; `writer.py` / `changelist.py` /
`resolve.py` / `display.py` / `app.py` / `workspace.py` and
`pyproject.toml` / `requirements.txt` are byte-unchanged; no new dependency.
Awaiting approval before starting increment 11.
