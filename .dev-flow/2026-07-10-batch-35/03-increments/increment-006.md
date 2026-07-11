# Batch-35 — Increment 6 (Inc-6): registry completion — AT-053b + TC-318 report half (test-only)

> HLR-053 / LLR-053.6 / LLR-055.4 on `feat/batch-35-report-filter` @ `e15b744`
> (Inc-0..5 committed; all product code landed). Adds the two verification
> nodes the C-18 registry reconciliation flagged missing: the redefined
> AT-053b (Q-3) and the `report_service` half of TC-318. Zero production
> edits.

## 1. What changed

- **`tests/test_tui_report_filter_surface.py`** (pure append + 1 docstring
  census bullet + `import re`):
  - NEW helper `_assert_md_table_rows_intact` — the batch-34
    split-on-unescaped-pipes idiom generalized: every contiguous MD table
    block must keep ONE unescaped-pipe count across all its rows.
  - **AT-053b** (`test_at_053b_hostile_valid_filter_proceeds_sanitized_everywhere`)
    — the Q-3 REDEFINED node: a VALID filter whose FILENAME is
    markup-hostile (`` [boom]`b`.json `` — brackets + backticks,
    Windows-legal; NTFS forbids `|`/`<`/`>` in names) and whose PATTERNS
    carry the full hostile corpus (`a|b`, backticks, `<b>bold</b>`,
    `\x01` ctl byte, and the header-forging line
    `"x\n## Report filter applied"`), selected through the REAL dropdown,
    driven through BOTH shipped triggers (key `b` + Generate) under the
    declared clock pin. Asserts: (a) generation PROCEEDS on both kinds
    (3 files written, no `refused` status); (b) the selection
    confirmation renders the filename literally through the markup-inert
    log funnel (LLR-053.6, Q-7 — the confirmation carries the filename);
    (c) ALL THREE written files re-read — before/after MD + HTML +
    project report — asserting LLR-055.4 sanitation: literal name in
    each audit header, `\x01` absent, no raw `<b>` in the HTML, the
    audit heading exactly ONCE at its pinned first-block-after-title
    position (S-F6 anti-forgery, line-anchored so a sanitized inline
    echo cannot false-fail), and MD table cell counts intact in both MD
    files.
- **`tests/test_report_service.py`** (pure append + `import json`):
  - **TC-318 report half**
    (`test_tc318_hostile_filter_name_and_patterns_sanitized`) — unit
    level: matcher `source_name = "a|b*[x]\x01\x1b.json"` + the hostile
    pattern corpus through `generate_project_report` on the TC-314
    fixture, TWICE — a MATCHING run (header renders; pinned position;
    `- Filter file: a|b*[x].json` ctl-stripped literal; a real
    `shown 1 of 2` count proving the run matched) and a ZERO-MATCH run
    (notice renders: `filter matched 0 of 2 items` ×2 +
    `0 of 3` ×1 under the same sanitized header). Both files: no raw
    `\x01`/`\x1b`, audit heading exactly once, no `Forged` heading/echo,
    `## Variant inventory` + `## Consolidated overview` intact.
    Deliberately covers what the Inc-2 diff half
    (`test_tc318_hostile_filter_name_sanitized_md_html`) does not — the
    `report_service` audit header + notice; no case duplicated.

## 2. Files modified

1. `tests/test_tui_report_filter_surface.py`
2. `tests/test_report_service.py`

File cap: 2/5 (+ this mandated dev-flow record). Engine-frozen set
untouched (`tests/test_engine_unchanged.py` → `1 passed in 0.06s`).
Zero production files touched — test-only increment.

## 3. How to test

```bash
# the two new nodes
python -m pytest "tests/test_report_service.py" "tests/test_tui_report_filter_surface.py" -k "tc318 or at_053b" -q
# engine-frozen guard
python -m pytest tests/test_engine_unchanged.py -q
# full fast suite
python -m pytest -q -m "not slow"
# lint
python -m ruff check tests/test_tui_report_filter_surface.py tests/test_report_service.py
```

## 4. Test results (real output)

- **New nodes GREEN** (registry nodes over already-landed Inc-0..5
  product code — GREEN-on-write is the expected shape; liveness proven
  by the counterfactuals below):

```
python -m pytest tests/test_report_service.py -k tc318 tests/test_tui_report_filter_surface.py -k "tc318 or at_053b" -q
2 passed, 51 deselected in 6.42s
```

- **Counterfactual RED proof (mandated).** Scratch file
  `tests/test_cf_scratch_inc6.py` (written, run ONCE, deleted — no
  stash at any point):
  - **CF-1 (TC-318):** `report_service._strip_ctl_local` monkeypatched
    to identity → the node's ctl assertion goes RED:

```
E       AssertionError: TC-318 counterfactual: raw control byte reached the file
E       assert ('\x01' not in '# Project r...onfidence)\n'
FAILED tests/test_cf_scratch_inc6.py::test_cf1_tc318_neutered_ctl_strip_goes_red
```

  - **CF-2 (AT-053b):** the app's `resolve_report_filter` seam wrapped
    to stamp a ctl-bearing `source_name` (simulating a POSIX-legal
    hostile filename NTFS cannot host) + BOTH file-side sanitizers
    (`report_service._strip_ctl_local`, `diff_report_service._strip_ctl`)
    neutered to identity → the AT's file re-read assertions go RED:

```
E           AssertionError: AT-053b counterfactual: raw control byte reached 20260710T120000Z-before-after-report.html
FAILED tests/test_cf_scratch_inc6.py::test_cf2_at053b_neutered_sanitizers_go_red
2 failed in 6.28s
```

  Honesty note on residual vacuity: AT-053b's `\x01`-absent /
  `<b>`-absent file assertions cannot fail TODAY via the filename arm on
  NTFS (ctl bytes and `<`/`>` are unrepresentable in Windows filenames)
  and the patterns are not echoed by the current renderers — CF-2 is the
  strongest constructible counterfactual: it proves the assertions
  discriminate the live sanitizer path the moment hostile text DOES
  reach the writers (POSIX filenames, or a future pattern-echoing
  surface). The exactly-once pinned-position heading, the literal-name,
  the literal-confirmation, and the table-integrity assertions are live
  against the shipped surfaces directly.

- **ruff**: `python -m ruff check tests/test_tui_report_filter_surface.py
  tests/test_report_service.py` → `All checks passed!`, exit 0.
- **Engine-frozen**: `tests/test_engine_unchanged.py` → `1 passed in
  0.06s`, exit 0.
- **Full fast suite**: `python -m pytest -q -m "not slow"` (single
  invocation; harness auto-backgrounded — the tail below is that one
  run's output, no re-run):

```
1335 passed, 2 skipped, 21 deselected, 4 xfailed, 1 xpassed, 1 warning in 678.35s (0:11:18)
```

  Arithmetic: Inc-5 base 1333 passed + 2 new nodes (AT-053b, TC-318
  report half) = **1335 passed**; 2 skipped / 4 xfailed / 1 xpassed
  unchanged (the declared Inc-5 snapshot state, untouched).

## 5. Risks

- **AT-053b pins exact header-block line positions** (`lines[2]`,
  `<h1>`+1) — intentional (S-F6 is a position contract, TC-312/TC-314
  precedent), but any future re-layout of the report head will need a
  censused supersede here too.
- **`_assert_md_table_rows_intact` assumes adjacent MD lines starting
  with `|` belong to one table** — true for both current formats
  (tables are blank-line/heading separated); a future format placing two
  different-width tables back-to-back without a separator would need the
  helper split per-table.
- **Windows filename limits** shrink the filename-arm hostility corpus
  (no ctl / `|` / `<` / `>` in NTFS names); the pattern arm + CF-2 cover
  the gap, recorded above.

## 6. Pending items

- Operator format docs + REQUIREMENTS.md `R-RPT-FILTER-001` /
  `R-TUI-045` ledger rows — the docs increment per PLAN.
- Canonical-CI snapshot regen for the Inc-5 patch cell(s) post-merge +
  mark retirement (unchanged from Inc-5).

## 7. Suggested next task

Batch-35 Phase-4 validation gate: full §5.2 registry sweep (now
complete on the AT/TC side), REQUIREMENTS.md ledger rows, format docs,
and the batch acceptance checklist (§5.3).

## Ledger delta

Base 1333 + 2 new = **1335 passed** under `-m "not slow"` (AT-053b,
TC-318 report half); 2 skipped / 4 xfailed / 1 xpassed unchanged; **0
existing tests modified, 0 deletions** (both files pure append; the only
non-append lines are the module-docstring census bullet, `import re`,
and `import json`); engine-frozen set untouched; 0 production edits.

## Evidence checklist

- [x] Tests/type checks/lint pass — full-suite tail above (exit 0);
      ruff `All checks passed!`.
- [x] No secrets in code or output — synthetic fixtures only.
- [x] No destructive commands run — no stash, no reset; scratch
      counterfactual file deleted after recording (created by this
      increment, own-mess cleanup).
- [x] File count within cap — 2/5 + the mandated increment record.
- [x] Review packet attached — this document (§1-§7).
