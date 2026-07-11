# Batch-35 — Increment 1 (Inc-1): report filter parse + match engine

> Net-new module increment on `feat/batch-35-report-filter` @ `92df3f4` (Inc-0 goldens
> committed). Implements LLR-053.1/.2/.3/.4/.7 (§6.2 D-7/D-8/D-10, F-1/F-2, Q-9/Q-10,
> S-F2/S-F4). No product file outside the new module is touched — the Inc-0
> byte-identity goldens stand guard over both report paths.

## 1. What changed

- **NEW `s19_app/tui/services/report_filter.py`** — the filter engine, mirroring the
  `crc_config.py` operations-input idiom (D-7):
  - `ReportFilter` (frozen dataclass) — the PARSED form: `symbols` patterns +
    half-open `addresses` ranges (LLR-053.1).
  - `ReportFilterMatcher` (frozen dataclass) — the RESOLVED form (LLR-053.7 / D-9):
    patterns + a pre-built sorted matched-address index over the MERGED
    (disjoint) union of explicit ranges and name-matched record extents.
    Classification methods `matches_symbol` / `matches_range` / `matches_item`
    never raise for any input shape (S-F4). Range intersection consumes
    `build_sorted_range_index` / `address_in_sorted_ranges` from the
    engine-frozen `range_index.py` (imported, never modified); the
    "range-starting-inside-[a,b)" arm is a `bisect` over the merged index
    (merging is required because `range_index` membership assumes
    non-overlapping ranges, while extents and explicit ranges may overlap).
  - `read_report_filter_text(path, base_dir, size_probe)` — resolve via
    `resolve_input_path`, refuse symlink/non-regular file AT READ TIME (S-F2),
    probe the filter-specific `REPORT_FILTER_SIZE_CAP_BYTES = 4 MiB` cap BEFORE
    reading (S-F3), catch `OSError`/`UnicodeDecodeError`; one named error per
    fault, never raises (LLR-053.2).
  - `parse_report_filter(text)` — envelope `s19app-report-filter` v1.0,
    unknown-key/type/domain checks (`0 <= start < end <= 2^32`, hex-or-int),
    ceilings 4096/4096 (LLR-053.3 / D-8), MULTI-error collection (one named
    diagnostic per fault — deliberate divergence from crc_config's single-error
    profile, per the HLR-053 "one named diagnostic per fault" statement).
    Empty include lists are VALID (D-10). `CAL_[` is accepted (Q-10).
  - `resolve_report_filter(filter, a2l_records, mac_records)` — F-1 extents
    `[addr, addr + (byte_size if positive int else 1))`; non-dict records,
    non-int/bool addresses, non-str names skipped; hostile collections
    swallowed (never-raise, S-F4). Match rule (a): `s == pattern or
    fnmatchcase(s, pattern)` (F-2 equality short-circuit).
- **NEW `tests/test_report_filter.py`** — 56 tests: TC-307 (valid round-trip,
  hex/int equivalence, D-10 zero-match, file round-trip), TC-308
  (one-error-per-fault matrix incl. the 7-fault file → ≥7 named diagnostics,
  `CAL_[` accepted), TC-309 (pre-read cap via the crc_config size-probe idiom,
  cap boundary-exact, symlink refusal with the repo's skip idiom, non-UTF-8,
  malformed/empty JSON, 4096/4097 ceilings both lists), TC-310 (the 8-combination
  (a)/(b)/(c) truth table through the resolved matcher, `fnmatchcase`
  case-sensitivity pin, F-1 tail-byte + end-exclusive negative twin, Q-9
  byte_size None/0/negative/non-int → extent 1, MAC-point vs A2L-extent
  divergence, F-2 `PAR[0]` equality + glob pins, Q-10 bracket pin, S-F4 hostile
  record/argument corpus).

### Ambiguity flagged for the gate (implemented literally, not redesigned)

LLR-053.1's reject enumeration does NOT list a missing `include` key (or missing
`symbols`/`addresses` keys inside it) — only wrong/missing format/version, unknown
keys, non-list/non-string/non-parsable/domain faults. Combined with D-10 ("empty
include lists are VALID"), this increment ACCEPTS a missing `include` (or a missing
inner list) as an empty list. No test pins the missing-key case (only the
squarely-specified present-but-empty case is pinned), so the gate can tighten it to
a rejection without superseding any test.

## 2. Files modified

1. `s19_app/tui/services/report_filter.py` — NEW (module described above).
2. `tests/test_report_filter.py` — NEW (56 tests, TC-307..TC-310).

File cap: 2/5 (this report file is the mandated dev-flow record, not a code file).
Engine-frozen set untouched: `range_index.py` consumed via import only;
`git status` shows only the two new files.

## 3. How to test

```bash
# scoped
python -m pytest tests/test_report_filter.py -q
# full fast suite
python -m pytest -q -m "not slow"
# lint
python -m ruff check s19_app/tui/services/report_filter.py tests/test_report_filter.py
```

## 4. Test results (real output)

- RED-first (trigger-absent counterfactual — module moved aside, one foreground run):

```
    from s19_app.tui.services.report_filter import (
E   ModuleNotFoundError: No module named 's19_app.tui.services.report_filter'
=========================== short test summary info ===========================
ERROR tests/test_report_filter.py
!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
1 error in 0.54s
```

  Module restored and verified present before proceeding.
- Scoped run: `56 passed in 0.29s`, exit 0. (No skips — symlink creation succeeded
  on this machine, so the symlink-refusal test executed for real.)
- Full fast suite: `1302 passed, 2 skipped, 21 deselected, 3 xfailed in 723.53s
  (0:12:03)`, `31 snapshots passed`, exit 0 — base 1246 + 56 new, skips/xfails
  unchanged from the Inc-0 baseline. (Harness auto-backgrounded the single pytest
  invocation; the exit code and summary were read from that one run's output —
  no re-run, no parallel duplicate.)
- `ruff check` on both new files: `All checks passed!`, exit 0.

### Process incident (recorded, resolved)

The first RED-evidence attempt used `git stash push -- <new file>`, which stashed
NOTHING (the file was untracked) and the follow-up `git stash pop` applied a
PRE-EXISTING batch-29 stash, conflicting `.dev-flow/state.json`. Resolved: the
conflicted path was restored to HEAD, the batch-29 stash entry (`stash@{0}`) is
preserved untouched, `git diff HEAD -- .dev-flow/state.json` is empty, and the
RED evidence was re-captured with the move-aside method instead. No further
`git stash` use in this increment.

## 5. Risks

- **Missing-`include` acceptance** — flagged ambiguity above; behavior is
  deliberately un-pinned by tests so the gate can tighten it cheaply.
- **Multi-error vs crc_config single-error** — the two operations-input parsers now
  differ in error-list cardinality. Intentional (HLR-053 requires one diagnostic per
  fault; crc_config's LLR-004.1 requires exactly one), but worth a docs note when the
  format documentation lands (later increment).
- **Merged-index intersection arm uses `bisect` directly** — LLR-053.4 names the
  three `range_index` functions for membership; `range_in_sorted_ranges` tests
  CONTAINMENT, not intersection, so the "matched range starts inside the item" arm
  is a two-line `bisect_right` over the `build_sorted_range_index` output
  (documented in the method's docstring). No engine edit.
- Wiring (composer kwarg, ReportOptions field, selection UX, audit header) is NOT in
  this increment — the module is dark code until Inc-2+; the Inc-0 goldens prove the
  report paths are byte-unchanged.

## 6. Pending items

- Gate call on the missing-`include` ambiguity (accept-as-empty vs reject).
- Format documentation for operators (envelope, extent semantics, F-2 over-match
  note, Q-10 bracket note) — belongs with the UX increment.
- LLR-053.4 perf smoke (4096-pattern worst case) — §6.3 risk 6, deferred to the
  increment that wires the matcher into a report run.

## 7. Suggested next task

Batch-35 Inc-2 per PLAN: before/after wiring — `compose_before_after_report`
`report_filter` kwarg (LLR-054.1), filtered linkage rows + hex windows with
filter-before-merge (LLR-054.2), audit header + zero-match notice (LLR-054.3),
guarded by the Inc-0 AT-054b golden.

## Ledger delta

Base 1246 + 56 new = **1302** (full fast suite confirms exactly). +56 TC nodes
(TC-307..TC-310 across 8 test classes), 0 existing tests modified, 0 deletions,
engine-frozen set untouched.

## Evidence checklist

- [x] Tests/type checks/lint pass — scoped `56 passed` exit 0; full suite `1302 passed, 2 skipped, 21 deselected, 3 xfailed`, 31 snapshots, exit 0; `ruff check` both files clean.
- [x] No secrets in code or output — synthetic JSON/symbol fixtures only.
- [x] No destructive commands run without approval — the stash incident was restorative (conflicted file reset to HEAD; pre-existing stash preserved), recorded above.
- [x] File count within cap — 2/5 code files + this mandated report.
- [x] Review packet attached — this file (sections 1-7).
