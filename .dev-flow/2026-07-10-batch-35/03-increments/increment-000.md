# Batch-35 — Increment 0 (Inc-0): byte-identity guard goldens (AT-054b, AT-055b)

> Test-only increment at the batch base revision `79699a5` — no product edits exist yet,
> so the goldens captured here ARE the base-revision output (LLR-054.4 / LLR-055.3).
> Toolchain entry gate: `pytest 8.4.2`, `ruff 0.8.4` — both verified before any edit.

## 1. What changed

Two byte-identity guard ATs plus their golden fixtures, both driving the SHIPPED surfaces:

- **AT-054b** (`tests/test_before_after_report.py`) — drives the full AT-038a chain
  (load image → patch-panel apply → save-back confirm → key `b`) under the declared
  fixed-clock environment pin and asserts the written MD+HTML pair equals the goldens
  captured in this increment. Guard for LLR-054.4 (HLR-054 no-filter byte-identity).
- **AT-055b** (`tests/test_tui_report_seam.py` — the file that owns the
  ReportViewerScreen Generate pilot idiom, per the HLR-055 provisional path) — drives
  the AC-A1 seam (project load → `action_view_reports` → real `#report_generate`
  button → worker drain) under the pin and asserts the written project report equals
  its golden. Guard for LLR-055.3 (HLR-055 no-filter byte-identity).
- New golden home `tests/goldens/batch35/` (no pre-existing golden-file convention in
  `tests/` beyond the SVG `__snapshots__`; documented in both test docstrings — no
  README file added).

### Pinned clock symbols (the LLR-054.4/055.3 environment pin, exact)

| Flow | Pinned symbol | Why |
|------|---------------|-----|
| `b`-key (AT-054b) | `s19_app.tui.services.diff_report_service._default_now` → fixed `2026-07-10T12:00:00Z` | THE default-clock seam BOTH generators resolve when no `now_fn` is passed (`generate_diff_report` diff_report_service.py:1127, `generate_diff_report_html` :1664). The handler passes none (app.py:1868-1873); `compose_before_after_report` forwards `now_fn=None` untouched (before_after_service.py:344). |
| `b`-key (AT-054b) | `s19_app.tui.changes.apply.datetime` → `_FixedApplyDatetime` (datetime subclass, fixed `now`) | DISCOVERED second clock: `apply_change_document` stamps `ChangeSummary.timestamp_utc` via an inline `datetime.now(timezone.utc)` default lambda (changes/apply.py:313-314, :359 — no `_default_now` symbol exists there), and both report formats print it as `Applied (UTC)` (diff_report_service.py:378 MD, :1257 HTML). Without this pin the pair is not byte-stable. |
| Generate (AT-055b) | `s19_app.tui.services.report_service._default_now` → fixed `2026-07-10T12:00:00Z` | The `NowFn` seam (report_service.py:125-140), resolved at :1202 when the worker passes no `now_fn` (app.py:2372-2374 passes none). |

All pins are `pytest.MonkeyPatch.setattr` on the module attributes, applied inside the
per-test drive helpers — no leakage between tests, zero shipped-path change.

### DEVIATION FLAG for the gate — canonical-form byte identity, not raw-byte identity

The requirement wording (`bytes(run) == bytes(golden)`) is **infeasible for raw file
bytes through the shipped surface**, for two environment reasons proven by a
double-run probe (two runs in different tmp roots, canonical-compared → IDENTICAL;
raw-compared → differ only in the two classes below):

1. **Absolute run-root paths in content.** `_active_project_dir()` resolves absolute
   (app.py:1148); the reports embed the per-run pytest tmp root in 4 path lines
   (before/after MD+HTML: Image A/B inventory + provenance before/after) and 1 line
   (project report: Modifications change-doc/saved-as). `tmp_path` differs every run
   and every machine.
2. **Platform newline translation.** All three writers emit `"\n".join(lines)` via
   `Path.write_text` with no `newline=` pin (diff_report_service.py:1153, :1705,
   report_service.py:1242) → CRLF on Windows, LF on ubuntu CI. A Windows-captured raw
   golden can never equal CI output.

Resolution implemented (declared in both AT docstrings as part of the environment
pin): equality is asserted on `_canonical_report_bytes(raw, run_root)` — (a) CRLF→LF
undo, (b) every spelling of the per-run root replaced by `<RUN-ROOT>`, (c) path
separators normalized to `/` ONLY inside `<RUN-ROOT>…` spans (regex-bounded, so
content bytes — including the batch-34 `\|` linkage-cell escapes — are never
rewritten). The same function transforms both the captured golden and the observed
run, and the golden read applies the CRLF undo too (shields `core.autocrlf=true`
checkout translation). Every byte outside these two environment classes is compared
exact, so the guard still catches any generator drift a later increment introduces.
On Linux CI the transform is a near-no-op (no CRLF, no backslashes).

**If the gate rejects this interpretation of LLR-054.4/055.3, the alternative is a
§6.5 requirement amendment or a production `newline="\n"` pin + relative-path scheme —
both out of this increment's authority.** Recommended companion (1 line, not done —
file cap): extend `.gitattributes` with `tests/goldens/** text eol=lf`, mirroring the
batch-25 SVG-baseline precedent.

## 2. Files modified

1. `tests/test_before_after_report.py` — additions only (AT-054b + `_FixedApplyDatetime`, `_canonical_report_bytes`, `_drive_bkey_report_pair`; no existing test touched).
2. `tests/test_tui_report_seam.py` — additions only (AT-055b + twin helpers; two import lines added: `datetime`/`timezone`, `pytest`).
3. `tests/goldens/batch35/at054b-before-after-report.md` — NEW golden, 3,899 bytes.
4. `tests/goldens/batch35/at054b-before-after-report.html` — NEW golden, 4,877 bytes.
5. `tests/goldens/batch35/at055b-project-report.md` — NEW golden, 2,721 bytes.

File cap: 5/5 (this report file is the mandated dev-flow record, not a code file).
Goldens were captured by RUNNING each pinned flow once at `79699a5` through the SAME
drive + canonicalization helpers the ATs import (a scratchpad capture script imported
the test modules — capture == test behavior by construction).

## 3. How to test

```bash
# the two new guards
python -m pytest "tests/test_before_after_report.py::test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden" "tests/test_tui_report_seam.py::test_at_055b_no_filter_generate_report_byte_identical_to_golden" -q
# scoped suites
python -m pytest tests/test_before_after_report.py tests/test_report_service.py tests/test_tui_report_seam.py -q
# full fast suite
python -m pytest -q -m "not slow"
```

## 4. Test results (real output)

- New ATs (bare run, exit code read): `2 passed in 4.39s`, `EXIT=0`.
- Scoped suites: `68 passed in 77.57s (0:01:17)`, `EXIT=0`.
- Full fast suite (orchestrator's independent bare run at the gate — AUTHORITATIVE):
  `1246 passed, 2 skipped, 21 deselected, 3 xfailed in 703.81s`, `31 snapshots passed`,
  `EXIT=0`. Reconciles the ledger exactly: batch-34 baseline 1244 + the 2 new ATs; skips
  and xfails unchanged from the baseline. (The implementing agent's earlier figure of
  "15 skipped, 2 xfailed" did not reproduce and is superseded by this run.)
- `ruff check` on both touched test files: `All checks passed!`, exit 0.

### Double-proof (batch-24 control) — one-byte perturbation of EACH golden → RED → restore → GREEN

Perturbations: XOR 0x01 at the file midpoint (offsets 1949 / 2438 / 1360).

RED evidence, MD goldens (both ATs, one run):

```
E           AssertionError: AT-054b: unfiltered md report bytes drifted from golden at054b-before-after-report.md (LLR-054.4 byte-identity, canonical form)
E             At index 1949 diff: b'.' != b'/'
E       AssertionError: AT-055b: unfiltered project-report bytes drifted from golden at055b-project-report.md (LLR-055.3 byte-identity, canonical form)
E             At index 1360 diff: b')' != b'('
FAILED tests/test_before_after_report.py::test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden
FAILED tests/test_tui_report_seam.py::test_at_055b_no_filter_generate_report_byte_identical_to_golden
```

RED evidence, HTML golden (MD goldens restored first so the HTML assert is reached —
the loop asserts MD before HTML):

```
E           AssertionError: AT-054b: unfiltered html report bytes drifted from golden at054b-before-after-report.html (LLR-054.4 byte-identity, canonical form)
E             At index 2438 diff: b' ' != b'!'
FAILED tests/test_before_after_report.py::test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden
```

After restoring all three: `2 passed in 4.51s`, `EXIT=0`. All three equality
assertions are proven live.

## 5. Risks

- **Canonical-form deviation** (see flag above) — needs explicit gate ratification.
- **Helper duplication**: `_canonical_report_bytes` + constants are duplicated across
  the two test files (no shared test-util module exists; a new one would be a 6th
  file). If batch-35 later ATs need it a third time, factor then.
- **Golden staleness by design**: any INTENDED change to unfiltered report bytes in a
  later batch must regenerate these goldens consciously (that is the guard working).
- **`apply.datetime` pin** patches a non-service module attribute (`changes/apply.py`
  has no injectable seam at its default). Test-side only; documented in the AT.
- Goldens will checkout as CRLF on Windows clones (`core.autocrlf=true`, no
  `.gitattributes` rule yet) — harmless to the ATs (CRLF undo on golden read) but a
  one-line `.gitattributes` follow-up keeps them byte-stable on disk.

## 6. Pending items

- Gate ratification of the canonical-form interpretation of LLR-054.4/055.3 (or a
  §6.5 amendment recording it).
- Optional 1-line `.gitattributes` extension: `tests/goldens/** text eol=lf`.
- CI (ubuntu) confirmation run — local pass is Windows; the canonicalization is
  designed for both, but the PR run is the proof.

## 7. Suggested next task

Batch-35 Inc-1 per PLAN: the filter module (`s19_app/tui/services/report_filter.py`,
LLR-053.1/.2/.3/.4/.7 — parse, ceilings, never-raise, matcher) with TC-307..TC-310,
now protected by these goldens.

## Ledger delta

+2 AT nodes (AT-054b, AT-055b), +4 test helpers, +3 golden fixtures. 0 existing tests
modified, 0 deletions. Engine-frozen set untouched (test-only increment).

## Evidence checklist

- [x] Tests/type checks/lint pass — pytest counts above (bare runs, exit codes read); ruff clean on both touched files.
- [x] No secrets in code or output — synthetic S19 fixtures only.
- [x] No destructive commands run — perturb/restore confined to the new golden files.
- [x] File count within cap — 5/5 (2 tests + 3 goldens); this .dev-flow record is the mandated report.
- [x] Review packet attached — this file (sections 1-7).
