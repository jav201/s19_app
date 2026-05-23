# Increment 2 — fixtures + Textual snapshot harness skeleton

**Phase:** 3 — Implementation
**Increment:** 2 of N
**Date:** 2026-05-05
**Branch:** `claude/lucid-margulis-a63fd4`
**LLR target (test infra only — no product code change):**
- LLR-007.2 — three new per-class fixture builders unblock TC-062.a / TC-062.g / TC-062.h.
- LLR-007.4 — Textual snapshot harness skeleton + smoke test unblock TC-064 / TC-065.
- §6.3 R-7 (snapshot infra) and R-9 / Q-N04 (fixture-build allocation) closure noted in §6.

## 1. What changed

- Added three deterministic fixture builders in `tests/conftest.py` matching the existing `make_large_s19/a2l/mac` style (programmatic, `seed: int = 0` default, no static files under `tests/fixtures/`):
  - `make_overlap_s19_hex(tmp_path, *, seed=0) -> {"s19": Path, "hex": Path}` — minimal S19 + Intel HEX with overlapping data ranges (TC-062.a). New private helpers `_intel_hex_data_record` and `_intel_hex_eof_record` keep the Intel HEX emit logic local to `conftest.py`.
  - `make_duplicate_alias_mac(tmp_path, *, seed=0) -> Path` — MAC file with two distinct symbol names mapped to the same hex address (TC-062.g). Content is fixed; `seed` parameter retained for builder-style parity.
  - `make_corrupt_records(tmp_path, *, seed=0) -> {"s19": Path, "a2l": Path, "mac": Path}` — S19 with one corrupted-checksum record, A2L with a malformed CHARACTERISTIC missing `ECU_ADDRESS`, MAC with one invalid-hex line (TC-062.h).
- Added three corresponding `pytest.fixture` wrappers `overlap_s19_hex`, `duplicate_alias_mac`, `corrupt_records` that yield `tmp_path`-rooted artefacts, mirroring the `large_*` fixture pattern.
- Added the snapshot-harness skeleton to `tests/test_tui_app.py`:
  - `_query_issues_panel_codes(app)` helper that reads the rendered `Code` cell of every row in the `#validation_issues_list` `DataTable` via `DataTable.get_row_at`, in the row layout `(severity, code, artifact, symbol, address, line, message)` produced by `precompute_issue_datatable_payload`.
  - `test_snapshot_harness_renders_issues_panel` smoke test that:
    1. Parses the `large_project` artefacts via `S19File`, `parse_a2l_file`, `parse_mac_file`.
    2. Builds a real `ValidationReport` via `validate_artifact_consistency` (matching `validation_service.build_validation_report`).
    3. Spins up `S19TuiApp(base_dir=tmp_path)` headlessly inside `App.run_test()` (sync wrapper via `asyncio.run` — no pytest-asyncio dependency added).
    4. Populates `app._validation_issues` with the report's issues, calls `app.update_validation_issues_view()`, awaits `pilot.pause()`.
    5. Asserts the harness reads back at least one rendered code that intersects the report's `issues` codes.
  - The smoke test does NOT cover any of the eight cross-file classes individually — that is increment 5/6 work. It only proves the harness skeleton can drive the app, render the panel, and observe the widget tree.

No product code modified. No new pytest plugins added.

## 2. Files modified

| File | Change |
|---|---|
| `tests/conftest.py` | Added `_intel_hex_data_record`, `_intel_hex_eof_record`, `make_overlap_s19_hex`, `make_duplicate_alias_mac`, `make_corrupt_records`, and the three pytest.fixture wrappers. Existing builders untouched. |
| `tests/test_tui_app.py` | Added `_query_issues_panel_codes` helper and `test_snapshot_harness_renders_issues_panel` smoke test at the end of the file. Existing tests untouched. |
| `.dev-flow/03-increments/increment-002.md` | This review packet. |

File count: **3** (within the ≤5 cap). Aim of "2 source/test + packet" met.

## 3. How to test

```
pytest -q tests/
```

Targeted runs (optional):

```
pytest -v tests/test_tui_app.py::test_snapshot_harness_renders_issues_panel
pytest -v tests/conftest.py  # collection check only, no tests
```

## 4. Test results

Run on Windows 11 / Python 3.14.4 / pytest 9.0.3:

```
$ python -m pytest -q tests/
......ss................................................................ [ 39%]
........................................................................ [ 78%]
.......................................                                  [100%]
181 passed, 2 skipped in 5.07s
```

- **181 passed** (was 180; net +1 from the new smoke test).
- **2 skipped** (TC-047 NTFS-junction probe on non-Windows runners + the other pre-existing skip — unchanged).
- **0 failed.**

Independent ad-hoc verification that the three new builders produce files programmatically and deterministically:

```
$ python -c "from tests.conftest import make_overlap_s19_hex, make_duplicate_alias_mac, make_corrupt_records; ..."
overlap:   {'s19': '.../overlap.s19', 'hex': '.../overlap.hex'}
dup_alias: '.../dup_alias.mac'
corrupt:   {'s19': '.../corrupt.s19', 'a2l': '.../corrupt.a2l', 'mac': '.../corrupt.mac'}
```

## 5. Risks

- **Smoke test scope is narrow on purpose.** It populates `_validation_issues` directly rather than awaiting the worker thread that runs in production. This is the safest harness skeleton — it validates the panel-query path without coupling the smoke test to load-pipeline timing. The per-class tests in increments 5/6 will need to either (a) drive the same direct-populate path with per-class report contents, or (b) drive an end-to-end load via `S19TuiApp(base_dir=..., load_path=...)` plus `pilot.pause()` until `app._validation_issues` settles. Option (a) is recommended for snapshot-style tests; option (b) for true integration tests.
- **Sync wrapper around `App.run_test()`.** Used `asyncio.run(_drive())` inside a sync `def test_*` because pytest-asyncio is not declared in `pyproject.toml`. Adding pytest-asyncio later would let the parametric per-class snapshot tests be `async def` directly, but this increment intentionally avoids new deps.
- **Determinism of the new builders.** `make_overlap_s19_hex` and `make_corrupt_records` use `random.Random(seed)` for the data bytes and emit ASCII-only S19/HEX records, so identical seeds produce byte-identical files. `make_duplicate_alias_mac` emits a fixed two-line content. None of the three depend on filesystem-ordering, time, or PRNG global state.
- **Fixtures are not yet wired to the eight cross-file classes.** This is by design — wiring is increment 5 (engine-side TC-062.a/g/h tests) and increment 6 (panel-render TC-064/TC-065). The builders' contract is "produces the smallest input that triggers exactly one class"; verifying that contract experimentally is increment 5's first task.
- **No product behaviour change.** Specifically: nothing under `s19_app/` was touched. The 180 tests that passed in increment 1.5 continue to pass identically.

## 6. Pending items

Closure notes folded in:

- **R-7 (snapshot infra) — closure note.** Harness skeleton (`_query_issues_panel_codes` helper + `test_snapshot_harness_renders_issues_panel` smoke test driven by `App.run_test()`) lands in this increment. Full LLR-007.4 parametric tests (TC-064 / TC-065 over the eight classes) land in increment 6.
- **R-9 / Q-N04 (fixture-build allocation) — closure note.** Three deterministic per-class builders added programmatically in `tests/conftest.py`, matching the existing `make_large_*` convention. **No `tests/fixtures/<class>/` directory was created.** The §5.2 / LLR-007.2 references in `.dev-flow/01-requirements.md` to `tests/fixtures/overlap_s19_hex/` etc. were location placeholders; per `CLAUDE.md` ("stress fixtures … exposes ... via deterministic generators ... do not introduce ad-hoc large-file builders"), conftest-resident builders are the correct home and the builders here follow the same shape as `make_large_s19/a2l/mac`. This satisfies the LLR-007.2 batch acceptance bullet ("per-class fixtures present in `tests/fixtures/`") in spirit — the fixtures are present and deterministic; only their on-disk location differs from the early-iteration document, and conftest is the project-canonical location.

Items deferred to follow-up increments (NOT this increment's scope):

- **Increment 3 — issue-message scrubbing implementation + tests (LLR-002.3).** See §7. Adds control-character stripping and the 500-character cap to `validation/rules.py`, plus `class TestIssueMessageScrubbing` in `tests/test_validation_engine.py`.
- **Increment 5 — engine-side cross-file TC-062.a/g/h tests** wiring the three new builders to `validate_artifact_consistency` assertions on `MAC_DUPLICATE_ADDRESS` (warning policy), `CROSS_S19_HEX_OVERLAP` (or recommended new code per LLR-007.1), and parsed-record corruption codes (`MAC_PARSE_ERROR`, A2L structure code).
- **Increment 6 — panel-render TC-064/TC-065** parametric tests reusing `_query_issues_panel_codes` over the eight cross-file classes.
- **Linux-CI portion of TC-044/045/046** (carried from `increment-001.md` A-N02 closure criterion) — to be confirmed on the next CI run.
- **Optional: pytest-asyncio adoption.** If the parametric panel-render tests become unwieldy with `asyncio.run()` wrappers, propose adding pytest-asyncio in increment 6 alongside the new test file. Not required.

## 7. Suggested next task

**Phase 3 increment 3 — issue-message scrubbing implementation + tests (LLR-002.3).**

Scope (≤5 files):
- `s19_app/validation/rules.py` — add a small private helper (e.g. `_scrub_issue_message`) that strips `\n`, `\r`, `\t`, ANSI escape sequences `\x1b[...]`, and truncates to 500 characters; route every `ValidationIssue(message=...)` construction through it. Single-file product change.
- `tests/test_validation_engine.py` — add `class TestIssueMessageScrubbing` per LLR-002.3 acceptance criteria: (a) malformed MAC symbol with `\n` and ANSI sequences (log-injection vector), (b) A2L tag name longer than 500 chars (panel-disruption vector), (c) negative case confirming benign messages pass through unchanged.

This is the smallest remaining product change with the highest test-leverage payoff before increments 5 and 6 lean on the harness and fixtures landed here.
