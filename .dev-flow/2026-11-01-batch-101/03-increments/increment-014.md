# Increment 014 — Inc 14 · R-WHELP, R-LEGEND-011, R-DOC-README, R-DOC-SECURITY, R-DOC-RELNOTE, R-DOC-GUIDE · help, legend and README describe the shipped app; SECURITY.md; 1.0.0 release notes

| Field | Value |
|---|---|
| Batch | 2026-11-01-batch-101 |
| Increment | 014 |
| Lane (if the batch forked) | — (no fork) |
| Requirement(s) | R-WHELP.7, .12, .13, .14, .18–.26 · R-TUI-062.10.1 · R-LEGEND-011 · R-DOC-README.2, .3, .4 · R-DOC-SECURITY.1, .2 · R-DOC-RELNOTE.1–.14 · R-DOC-GUIDE.1, .2 |
| Acceptance | black-box cases R-WHELP.7/2, .12/2, .18/2, .19/2–.19/3, .20/2, .21/2, .22/2, .23/2, .24/2, R-TUI-062.10.1/2, R-LEGEND-011/1–/2 · white-box TC-707 (re-bodied), TC-1802 (re-bodied), AT-285 (extended) |
| Agent | `software-dev` |
| Date | 2026-11-06 |

---

## 1 · What changed

The shipped app's own words are made true. The six stale help sections of `WINDOW_HELP_SECTIONS` (`a2l`, `workspace`, `checks`, `crc_designer`, `reports`, `split_join_export`) and six Flow Builder steps are rewritten to match what the windows actually do; the Memory Map legend's two lines (`MAP_KEYS_LINE`, `MAP_REGION_ROW_FIELD_KEY`) stop naming keys the sheet does not handle; the README's window rail, key tables and window sections, plus new Check Editor / Flow Execution / Split / Join / Export sections, describe the real rails, keys and folders; a root `SECURITY.md` states the supported versions and the private reporting path; a root `CHANGELOG.md` holds the `## 1.0.0` release notes (the Inc 8 CRC note and the merged Inc 3 / 7 / 8 changes a 1.0.0rc1 user meets); and the user-guide passages and DOSSIER rows that quoted pre-1.0.0 text are corrected or marked `fixed in 1.0.0`. Two source files change, both text-only: no function, no signature, no import, no widget changes (0 functions, 3 constants, 0 new symbols). One new test file (`tests/test_b101_help_legend_docs.py`) and one support module pin the copy; three md-reading nodes are re-bodied so no test reads `help_sections.md` any more, and the README key guard counts the newly-listed `=`, `]`, `Ctrl+Q`, `Ctrl+P` keys. `SECURITY.md` is held out of the merge while private vulnerability reporting reads `{"enabled":false}`.

## 2 · Files modified

Committed: `git diff --stat main...HEAD` (51 files, +5693 / −405). Uncommitted at close: the re-audit section of `E5-coverage-audit.md`, `E5-mutants.md`, the 45 mutant transcripts, the re-audit edits of `02-test-cases.md`, `04-validation.md` and this packet. SOURCE files: **2 / 4**.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `.dev-flow/2026-11-01-batch-101/inc-14/01-requirements.md` | doc |  | EARS requirements (27 new rows) + Definitions (Help copy I14, Legend copy I14, K(w)) |
| `.dev-flow/2026-11-01-batch-101/inc-14/02-test-cases.md` | doc |  | 74 ISO 29119-3 cases over the 27 rows; audited at E5 + re-audit records-only corrections |
| `.dev-flow/2026-11-01-batch-101/inc-14/E1-rulings.md` | doc |  | E1 rulings, scope, canon changes, decisions D-1 … D-11 + orchestrator rulings + E3 folds |
| `.dev-flow/2026-11-01-batch-101/inc-14/E1-slice.md` | doc |  | E1 implementation slice: every file and function to change, counted and mapped |
| `.dev-flow/2026-11-01-batch-101/inc-14/E3-architect.md` | doc |  | E3 design review: round 1 FAIL (A-1 … A-6 MAJOR) → round 2 PASS-WITH-NOTES |
| `.dev-flow/2026-11-01-batch-101/inc-14/E3-rulings.md` | doc |  | E3 round-1/2 rulings + E4 addenda N-1 … N-3 |
| `.dev-flow/2026-11-01-batch-101/inc-14/E3-security.md` | doc |  | E3 design security review: PASS-WITH-NOTES, S-1 … S-8 |
| `.dev-flow/2026-11-01-batch-101/inc-14/E4-impl-notes-code.md` | doc |  | E4 implementer notes (code unit) |
| `.dev-flow/2026-11-01-batch-101/inc-14/E4-impl-notes-guide.md` | doc |  | E4 implementer notes (user guide unit) |
| `.dev-flow/2026-11-01-batch-101/inc-14/E4-impl-notes-top.md` | doc |  | E4 implementer notes (top-level documents unit) |
| `.dev-flow/2026-11-01-batch-101/inc-14/E4-integration-notes.md` | doc |  | E4 integration: GREEN on the LAN host, SR-1, OR-1 … OR-6, runs |
| `.dev-flow/2026-11-01-batch-101/inc-14/E4-tester-notes.md` | doc |  | Independent tester notes: RED on base, full/partial marks |
| `.dev-flow/2026-11-01-batch-101/inc-14/E5-code-review.md` | doc |  | E5 independent code review: PASS-WITH-NOTES, F1 … F8 |
| `.dev-flow/2026-11-01-batch-101/inc-14/E5-corrective-notes.md` | doc |  | E5 corrective pass: C-1 … C-9, final runs, the nine clauses |
| `.dev-flow/2026-11-01-batch-101/inc-14/E5-coverage-audit.md` | doc |  | Independent coverage audit + re-audit at `0bbb2c6` (uncommitted re-audit section) |
| `.dev-flow/2026-11-01-batch-101/inc-14/E5-rulings.md` | doc |  | E5 rulings C-1 … C-9 (binding) |
| `.dev-flow/2026-11-01-batch-101/inc-14/E5-security.md` | doc |  | E5 security review: OK for Inc 14 without the SECURITY.md group; BLOCK-UNTIL E5-1 for the group |
| `.dev-flow/2026-11-01-batch-101/inc-14/E5-mutants.md` | doc |  | E5 mutant table: 45/45 KILLED, 2 N/A (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-14/04-validation.md` | doc |  | This increment's validation record (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-14/steps.log` | doc |  | Stage log, models and UTC stamps (appended at close) |
| `.dev-flow/2026-11-01-batch-101/inc-14/codewire/graph-inc14.md` | doc |  | Code-wire graph: I/O blocks, interface table I-1 … I-16 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-c1-mutants-red-then-green.txt` | generated | US-HELP-1 | C-1 mutant proof: M1/M2 RED on the strengthened test, GREEN on the pre-E5 probe |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-int-07-inc14-reworked-guards-supporting.txt` | generated | US-HELP-1 | E5 int-07: 1 failed (hygiene redaction guard on a record line), 502 passed, 4 skipped |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-int-07b-hygiene-rerun-after-record-fix.txt` | generated | US-HELP-1 | E5 int-07b: hygiene rerun after the record fix, 65 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-int-08-importers-b97-b99-b100.txt` | generated | US-HELP-1 | E5 int-08: importers group B, 670 passed, 10 skipped |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-int-09-importers-legend-report-split.txt` | generated | US-LEGEND-1 | E5 int-09: importers group C, 274 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/gh-pvr.txt` | generated | US-SEC-1 | E5 `gh api` private-vulnerability-reporting read: `{"enabled":false}` |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-01-first-run.txt` | generated | US-HELP-1 | E4 first run: 6 failed, 227 passed, 3 skipped |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-02-group-a-inc14-and-guards.txt` | generated | US-HELP-1 | E4 group A + law guards: 505 passed, 3 skipped, 0 failed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-02x-combined-killed-at-timeout.txt` | generated | US-HELP-1 | E4 whole-GREEN-set run, stopped at ~31/40 min (host load) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-03-group-b-b97-b99-b100.txt` | generated | US-HELP-1 | E4 group B: 1 failed (load flake), 669 passed, 10 skipped |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-04-tc-b97-55-isolated-reruns.txt` | generated | US-HELP-1 | E4 TC-B97-55 isolated ×3: 2 passed × 3 |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-05-group-c-report-split-diff-snapshot.txt` | generated | US-LEGEND-1 | E4 group C: 1 failed (harness basetemp), 203 passed, 29 skipped |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-06-snapshot-rerun-pytest-basetemp.txt` | generated | US-LEGEND-1 | E4 snapshot rerun: 4 passed, 29 skipped |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/red-01-tester-base.txt` | generated | US-HELP-1 | Tester RED-proof on base: 56 failed, 16 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-01.txt` … `mut-47.txt` (45 files; M19/M24 have no transcript) | generated | US-HELP-1, US-LEGEND-1, US-README-1, US-SEC-1, US-REL-1, US-GUIDE-1 | E5 mutant battery transcripts: 45 KILLED, each restored byte-exact (uncommitted) |
| `s19_app/tui/legend.py` | source | US-LEGEND-1 | 0 functions; 2 constants changed: `MAP_KEYS_LINE`, `MAP_REGION_ROW_FIELD_KEY` + their comments |
| `s19_app/tui/window_help.py` | source | US-HELP-1 | 0 functions; 1 constant changed: `WINDOW_HELP_SECTIONS` — 6 entries rewritten whole + 6 Flow Builder steps; docstring/data-home comments stop calling the sections a port of `help_sections.md` |
| `CHANGELOG.md` | doc |  | New: `## 1.0.0` release notes (Inc 8 CRC note + merged Inc 3/7/8 changes; CRLF wording fixed at E5 C-8) |
| `README.md` | doc |  | Rail paragraph and window table, key tables, Patch Editor / A↔B Diff / Flow Builder / Operations / Projects / Workarea sections, new Check Editor / Flow Execution / Split / Join / Export sections, key spelling `^K`, wrapped at 80 columns, Documentation table gains `SECURITY.md` + `CHANGELOG.md` |
| `SECURITY.md` | doc |  | New: supported versions, private reporting path, scope; held out of the merge while the channel is closed |
| `docs/user-guide/DOSSIER.md` | doc |  | §5 rows F-16, F-28, F-30, F-37, F-38, F-41, F-42, F-49: fixed mark; F-28 reworded (F2) |
| `docs/user-guide/ch06-memory-map.md` | doc |  | 6.5 map-keys text + capture note |
| `docs/user-guide/ch16-reports.md` | doc |  | 16.1 Declared regions, 16.2 Markdown only |
| `docs/user-guide/ch17-flow-builder.md` | doc |  | 17.5 CRC block / Designer template + capture note; 17.11 later block |
| `docs/user-guide/ch18-flow-execution.md` | doc |  | 18.9 second-run copy |
| `docs/user-guide/ch19-help-palettes-settings.md` | doc |  | 19.1 help text + capture note |
| `docs/user-guide/ch21-html-reports.md` | doc |  | intro, 21.1 header/Runs bullets + capture notes, 21.2 escaping sentence, 21.5 |
| `tests/support/help_copy_i14.py` | test | US-HELP-1, US-LEGEND-1 | New: Help copy I14 and Legend copy I14, pinned |
| `tests/test_b101_help_legend_docs.py` | test | US-HELP-1, US-LEGEND-1, US-README-1, US-SEC-1, US-REL-1, US-GUIDE-1 | New: G — the 74 cases' full/partial nodes + the C-1 whole-label scoping + the `?`/`k` black-box nodes |
| `tests/test_changes_file_notation_help.py` | test | US-HELP-1 | tc1802 re-bodied (exact 12-key set, no md read); `_HELP_SECTIONS_MD` removed; F6 vacuous control now runs a detector |
| `tests/test_docs_canon.py` | test | US-README-1 | AT-285 helpers extended: `=` / `]` glyphs, inherited keys from `_merged_bindings`, palette-conditioned `ctrl+p` + monkeypatch negative control |
| `tests/test_id_registry.py` | test | US-HELP-1 | TC-607 `EXPECTED_SCANNED_TEST_FILES` 250 → 252 (measured) |
| `tests/test_window_usage_help.py` | test | US-HELP-1 | tc707 nodes re-bodied (copy, numbering, census, boundary); stale docstrings refreshed (F5) |

| Count | Value |
|---|---|
| **SOURCE files** | **2 / 4** |
| Test files | 6 (1 new + 1 support module + 4 re-bodied) |
| Doc files | 9 product docs + 21 record files |
| Config files | 0 |

The 2 source files are text-only (3 constants, 0 functions, 0 new symbols); the increment could not be cut smaller because the six stale help sections and the two legend lines are one shipped-surface correction.

## 3 · How to test

```bash
# focused set (LAN Linux host): the new file, the re-bodied files, the guards
env -u NO_COLOR PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. \
  python -m pytest -q -p no:cacheprovider -n 8 \
  tests/test_b101_help_legend_docs.py tests/test_window_usage_help.py \
  tests/test_changes_file_notation_help.py tests/test_docs_canon.py \
  tests/test_id_registry.py tests/test_suite_hygiene.py \
  tests/test_engine_unchanged.py tests/test_tui_directionb.py \
  tests/test_requirements_canon.py tests/test_b101_flow_ext_copy.py
# importers of window_help / legend (groups B and C)
python -m pytest -q -n 8 tests/test_b97_check_editor.py tests/test_b97_chips_help.py \
  tests/test_b97_flow_builder.py tests/test_b97_flow_execution.py tests/test_b97_key_bar.py \
  tests/test_b97_patch_editor.py tests/test_b97_width.py tests/test_b99_bytes_field.py \
  tests/test_b100_focus.py tests/test_b100_load_dialog.py \
  tests/test_legend_map_sheet.py tests/test_legend_n8.py tests/test_legend_two_pane.py \
  tests/test_legend_scope_and_logwidth.py tests/test_tui_legend.py tests/test_report_service.py \
  tests/test_segment_split_window.py tests/test_tui_diff_screen.py tests/test_tui_report_seam.py \
  tests/test_tui_theme.py
```

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** (cyclomatic ≥3, or crosses a declared module boundary) | `core` · `full` | none — 0 functions changed (3 constants, text only) | n/a |
| **A · white-box** TC-707 / TC-1802 / AT-285 ↔ rows | `core` · `full` | the 4 re-bodied tc707 nodes, tc1802, AT-285 helpers, and every `*_1_*` copy node of G | 505 passed, 3 skipped in int-02; 502 passed, 4 skipped in int-07 (the 1 failure is a record-leak guard, re-ran GREEN in int-07b) |
| **B · black-box** acceptance cases through the shipped surface | `core` · `full` | 12/2, 18/2, 19/2, 19/3, 20/2, 21/2, 22/2, 23/2, 24/2, 062.10.1/2, LEGEND-011/1–/2, 7/2 (`?`), 062.10.1/3 (`k`) | passed in int-02/int-07; 7/2 key-line arm `partial` (re-audit R.2 #2) |

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | the pre-Inc-14 product texts (base `b7b77c4`-equivalent): stale help copy, legend line, README/SECURITY/CHANGELOG/guide/findings text; README lacks `Ctrl+P`, `=`, `]`; `checks`/`a2l`/`split_join_export` step counts differ from the pins |
| Instrument | the new/changed tests run against a detached base worktree on the LAN Linux host (tester) |
| Where it ran | the LAN Linux host, conda env `s19ci`, Python 3.11.18 |
| Transcript | `evidence/inc-14/red-01-tester-base.txt` — 56 failed, 16 passed (72 nodes) |
| Restore proven by | n/a — RED run on a detached base worktree; nothing was mutated in the branch |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` |
| Arms resolved at baseline | 72 nodes run (the G file + 7 existing nodes) |
| Verdict granularity | per node id in the transcript; 56 named FAILED lines |
| Arms that stayed GREEN | the 16 honestly-green acceptance nodes (12/2, 18/2, 19/2, 19/3, 20/2, 21/2, 22/2, 23/2, 24/2, 062.10.1/2, RELNOTE 1/2, 2/2, 26/2, and the 3 guard nodes tc707 census/boundary, tc1802) — each already holds on base, and its teeth are the in-test negative controls |

| Field | Value |
|---|---|
| **RED counterfactual** | base texts (stale copy) made the new assertions fail — 56 of 72 nodes RED in `red-01-tester-base.txt`; the restore is n/a (the RED ran on a detached base worktree, not a mutated branch file) |

| Field | Value |
|---|---|
| **Mutation verdicts** | 47 product-text mutants (M01 … M47) minus 2 N/A (M19, M24) = **45 KILLED / 0 SURVIVED / 2 N/A**. Each applied one mutation to `window_help.py`, `legend.py`, `README.md`, `SECURITY.md`, `CHANGELOG.md` or `docs/user-guide/*.md`, ran the case's cited node(s), and restored byte-exact (sha256 before/after equal, `RESTORE_OK`). The 2 N/A are not product-text mutations: M19 is a behaviour change in `screens_directionb.py`; M24 is the code-side palette flag already exercised by the in-test negative control of `test_at285`. Table: `E5-mutants.md`; transcripts `evidence/inc-14/mut-*.txt` (45) |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| G copy nodes + re-bodied tc707/tc1802/AT-285 | the base tree's stale texts | 56 FAILED lines in `red-01-tester-base.txt` |
| C-1 whole-label scoping (`test_r_whelp_12_2_named_controls_exist`) | M1 Checks pane retitled `Peek`, M2 A2L `Goto` → `Go` | `named controls not painted by their window: [('checks', 'Hex Peek')]` and `[('a2l', 'Goto')]` — `e5c-c1-mutants-red-then-green.txt` |
| the 16 case negative controls (tester harness) | each control's corruption | each named node RED, restore GREEN (E4-tester-notes §Harness validation) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 3 instruments (the RED-on-base battery, the C-1 mutant pair, the tester's 16 in-test negative controls), each shown RED before its PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the help modal (`#window_help_body`, `#window_help_keys`) | `test_tc706_affordance_opens_window_section_modal` (9 seats) and `test_r_whelp_7_2_question_mark_paints_the_approved_copy` (7 sections via `?`) compare the painted body to the numbered approved copy | passed (int-02, int-07) |
| the legend sheet (`Map keys` / `Region row` boxes) | `test_r_tui_062_10_1_3_k_paints_the_map_keys_line` and `test_r_legend_011_1_region_row_field_line` read the painted boxes | passed |
| `README.md`, `SECURITY.md`, `CHANGELOG.md`, `docs/user-guide/*.md`, `DOSSIER.md` | every `*_1_*` document case reads the shipped file's bytes and pins the exact substrings | passed (int-07) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifacts (help modal, legend sheet, the shipped documents), each asserted against the form its producer emitted (the painted widget, not the constant; the on-disk file, not the graph) |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 of the bytes at the cited path, taken 2026-11-06. Home: `.dev-flow/2026-11-01-batch-101/evidence/inc-14/`.

| Evidence artifact | Path (repo-relative) | SHA-256 |
|---|---|
| e5c-c1-mutants-red-then-green.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-c1-mutants-red-then-green.txt | 02be6f51c7baec8891b71dbac25c7b75c43eb92ee73aa9a5b9e6c047cded1b0e |
| e5c-int-07-inc14-reworked-guards-supporting.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-int-07-inc14-reworked-guards-supporting.txt | 05fe4bd5cb170a3797ca78e5533b2858be054a54dc40eccc44dcd483f47cff1b |
| e5c-int-07b-hygiene-rerun-after-record-fix.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-int-07b-hygiene-rerun-after-record-fix.txt | 5b618f827491eb869e720f4f428d6db147c148d491c066eb3ed437804267da88 |
| e5c-int-08-importers-b97-b99-b100.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-int-08-importers-b97-b99-b100.txt | b152d402ace27bb702110f98963c757b8d0fbd0358c7b9362847fe56a6db7f4a |
| e5c-int-09-importers-legend-report-split.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-int-09-importers-legend-report-split.txt | 05852c01556cf705096bb032142c25e0ed3cbffaedaaf96d3dfee351561dedf1 |
| gh-pvr.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/gh-pvr.txt | f4b4e4c07325d27276eee53fc40a54e4b36735bd0b4d729205d1f925c8d31ce2 |
| int-01-first-run.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/int-01-first-run.txt | ef210435f55eef5b1e9456cb12107cd8433d3598adf443c4a95fb0bd04570cbb |
| int-02-group-a-inc14-and-guards.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/int-02-group-a-inc14-and-guards.txt | 30f1ab9f05badd1c2742ae6374ecf88ad287334586678d27d6716157abb9c634 |
| int-02x-combined-killed-at-timeout.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/int-02x-combined-killed-at-timeout.txt | e3d2dd40732d52271e4e631fe4f0500cbf918c9c936802d678075d0da14cf0a5 |
| int-03-group-b-b97-b99-b100.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/int-03-group-b-b97-b99-b100.txt | be06992123c02c7ced275f43077998586efcb811d3b704a592df303cd3585b37 |
| int-04-tc-b97-55-isolated-reruns.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/int-04-tc-b97-55-isolated-reruns.txt | 61364aed20ea59d40c807808487aba03aba6ae27c38c3e4a990b182e97243619 |
| int-05-group-c-report-split-diff-snapshot.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/int-05-group-c-report-split-diff-snapshot.txt | 1aa9f48c8e5e3ac7afa0615d0421896e86694815d0d5124ed8674d8d5a28a5e2 |
| int-06-snapshot-rerun-pytest-basetemp.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/int-06-snapshot-rerun-pytest-basetemp.txt | 7998916f86f0bf529b1c33471e7f7d54e3726c59c14ac212903a9ca7914506a3 |
| red-01-tester-base.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/red-01-tester-base.txt | 3f1f1b4eddcaf13ad4da8f9d5ffba5b3c9bb6f61e9f2969224df61166d09e063 |
| mut-01.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-01.txt | eadf247f94eba33c2edd4f537a5eefb6f0647b48c75eac20b707902dcc5b1574 |
| mut-02.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-02.txt | ae16c437f98e213c688fcc23f3a2b011001ebc96c2d390b4c0c7b46be92e5130 |
| mut-03.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-03.txt | c48ea7edf5959cc53ea78b53288796ebf4159a023757512dddbdcd004711a267 |
| mut-04.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-04.txt | 673784a6ce6eb58cee15fb58e2508f7636c6ed15e7ed1645f63ff0bf21fbcded |
| mut-05.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-05.txt | cfb4357fe5a719905e6b7d2c05f83e12e95ff4849ba7fb0b43c7bd6583fddf77 |
| mut-06.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-06.txt | a5eff5255eb243220cdb57338c1ef24a47a9582bfe8228042e26a04c2f03ba3d |
| mut-07.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-07.txt | b763b4a67abd2d5c11a51f74599a3795954a3881b0590f22065dcd4dc95852d1 |
| mut-08.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-08.txt | 494de130d98c95da0bedb91b45670d7c556e190ae1ff917490f9b1e0344f4836 |
| mut-09.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-09.txt | eeebe35cb2c17912ce958fa63a9a7eb1ef8070f391dddce3e63a5d10d22fdbd9 |
| mut-10.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-10.txt | 3181e81bf1b9d4f9b48213dc03d70daf4038725174d2828c6bc55ef3e53b2e0d |
| mut-11.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-11.txt | d27361e9c641f40ed1f06f32e4f5befc50c53203d9992aa7f9bb5a6017aa131c |
| mut-12.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-12.txt | 8fecdb70a1ff1918ac17452ed2584d6c55ec8756f0524fe96bba25afe04c6b23 |
| mut-13.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-13.txt | 327dd6361bfbf091da5d0e0294e3bfae046037df75f49007fd97d788292bb74b |
| mut-14.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-14.txt | 4d757db9251d829604442c2ca1ea9f8ea5e3ec64477f01c4bc677c81bc432c3c |
| mut-15.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-15.txt | c8f8dddabfc6357196ef74c767e766b1b7c51360eeee8f13b7bb2c370f7ef699 |
| mut-16.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-16.txt | b7e71329bb8c923681827e99c44556e456981bf2936ba272270651c4c82f0af5 |
| mut-17.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-17.txt | 41ac3f981f924d6c624c9e6a9ec1d0a6d1294207e20e81fcd95a7bddc2a9fb9e |
| mut-18.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-18.txt | f6e2462032ac14c73ca3ab66a5f3e150418c9584f86789dbdbc1573b1653a523 |
| mut-20.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-20.txt | 7fc6bd8e98e61cd438f9079c6dcdf94215ce9cd451fe1a7c60fce5e0282ac18c |
| mut-21.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-21.txt | cd8f5c30427c169756d509bae01bb8cd8e9b9947e17e01bc88fff7a713e8d330 |
| mut-22.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-22.txt | ae2863e9c6d7b87cb4724f463bb8a406a7ffd47b3b7d55c21f3cecdeec025608 |
| mut-23.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-23.txt | 19daad84ef6760667b27d1e291bdcc96eb38ccef0c2d8c967e68b1ba1cc5daef |
| mut-25.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-25.txt | 1784d99cfcb58e41e731ecbaea792ced061fa529fb6f5b0db5121d2759a48253 |
| mut-26.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-26.txt | de32fb85ca14b1049526aaf3fbfc6be2f5849cc5d41224d31ccbbe1c4415691a |
| mut-27.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-27.txt | 288a16ec6f0a2a95bc1c7246190e884215ab82edcec8b0b0c0eedc52b3ccb056 |
| mut-28.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-28.txt | 1462d23dc93d8da353403b4e148d7b16c1fb518a94dc46361336081a5dce5ed0 |
| mut-29.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-29.txt | 9954e2c2bb01e42d561e9f6356ad1b7ab757734f979e8f1f04e54c05b92e7a27 |
| mut-30.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-30.txt | 9e5793d171825c5240a2c8a95437b5a8a2568a95fcca9ca7c59728ec8e7195f8 |
| mut-31.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-31.txt | 5b2e19cfac6b5b2ccecb1657fe52b98c7eb2bb5fb8fd039b0d82c4a2c1e89357 |
| mut-32.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-32.txt | 7ec3709b7d98527a07f605ecd6fbc939fb9e4bed8a2b469c4257671cbd20b789 |
| mut-33.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-33.txt | 1522898bea311af23774fe071c74578e7668d853af25307000a98193f8a940c1 |
| mut-34.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-34.txt | 5bfd6336e294900802a6d36c35b2b3af4a336f62795e2e0ce9dd68ccfd9a4b9e |
| mut-35.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-35.txt | c0e4baa407b2dcfd30ad7a3c923ef6d2f37141abac003fcc1338f538c7eb9ee5 |
| mut-36.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-36.txt | 55b979dbaecb4a2482a8822e807bce6ded486d2b10caf33ed345bb6673a551df |
| mut-37.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-37.txt | 2218c62d0f64a2809c413928c26862702aab4348cb02565c736799c4deff0084 |
| mut-38.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-38.txt | 15420be5f3f4fe85f2fa0d7f7e40a7ff8ea1666c8f263bc456c66805f2b6c14e |
| mut-39.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-39.txt | a99a79055ccb57303159eb66d1e5cadaddf46f94bc235382d39af21609d8db3c |
| mut-40.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-40.txt | 1226c226067e96883955ffbebb17f14ce58327cb43567c5b8fa1a96d65260cf1 |
| mut-41.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-41.txt | 5791ae3f774c676a42066a06b114f91c5182e10846d98022835d696602585a2f |
| mut-42.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-42.txt | faaccb7a04f2ed9928b7017d9338e6032a16e2e58914e468067ba445a9cdf82a |
| mut-43.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-43.txt | 83cb369505dbbe8f4d2372347158328136d199433597f4b1fdedc2d00ec9b6a0 |
| mut-44.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-44.txt | 1d45d7e75228436a06cdf943840f2bf77f4b2cec6730a7a2f95121213946035f |
| mut-45.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-45.txt | 04a4fdf996daafcb54e2a03ea52b77422edd24b696636cd898f9ba01a33b52ae |
| mut-46.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-46.txt | 918c1fe36f15e9fb9e0c3d946dbf0ad8bbfb278ddda56b49abb6e471b4aab0f1 |
| mut-47.txt | .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-47.txt | b53352bb617cc3874e201664a3d40466e11bf103dc201cbf0c7c275500c12c24 |

| Field | Value |
|---|---|
| **Evidence files** | 59 transcripts (14 run/evidence + 45 mutant), each cited with the digest of its stored bytes, all under the home `.dev-flow/2026-11-01-batch-101/evidence/inc-14/` |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — the stale-phrase absences (no `j k`/`select`/`↵ open hex`, no `not in a public issue` fallback, no `random` in the CHANGELOG Reports section, the 11 absent README stale claims, the 18 absent help stale phrases) and the key-line absence set (CRC Designer, Flow Builder, Reports paint no key lines) |
| If the result is an ABSENCE, what made the search wide enough | full-file scans of the shipped documents (the `*_1_*` cases read the whole file), and the `?`-route black-box node reads every changed section's painted body and key block |
| Guard labelled as protecting a CONCLUSION, not a behaviour | the `*_3_*` / `*_1_*` absent-phrase nodes (e.g. `test_r_whelp_12_3_no_stale_claim`, `test_r_doc_readme_4_1_no_stale_claim`); the 7/2 key-line absence set |
| Conjunctive criteria: one mutation per conjunct | each absence is its own pinned substring or set; the mutant battery mutates one phrase at a time (M04 … M06, M13, M27, M38, M43 … M44) |
| Synthetic instance of the absent case | the in-test negative controls append the forbidden phrase/fallback and assert RED (e.g. the SECURITY fallback controls, the GUIDE.1/12 moved-note controls) |
| **Positive control for every probe that returned an ABSENCE** | the tester's synthetic documents written from the requirement text turned all 40 document nodes GREEN; each of the 16 case mutations turned the named node RED and restore turned it GREEN |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rl "WINDOW_HELP_SECTIONS\|MAP_KEYS_LINE\|MAP_REGION_ROW_FIELD_KEY" tests/` | the re-bodied tc707/tc1802 nodes, G, `test_b97_chips_help.py`, `test_b97_key_bar.py`, `test_b99_bytes_field.py`, `test_b97_flow_execution.py`, `test_legend_map_sheet.py`, `test_legend_n8.py` — all read the constants, none pins a literal (E1-slice §3) |
| B2 file moved on disk | `help_sections.md` — the three md-reading nodes re-bodied so no test reads it | grep of `tests/`: 0 remaining readers (E1-rulings §3) |
| B3 byte-identical golden captures this source | `grep -E "j k|double-click|glyph" tests/__snapshots__/` | 0 hits — no SVG snapshot renders the legend sheet or a help window |
| B4 artifact produced here is consumed elsewhere | the documents (README/SECURITY/CHANGELOG/guide) — `tests/test_docs_canon.py` (AT-285) and `test_r_doc_readme_4_2_linked_documents_exist` read README links | the README key tables and link targets are the consumers |
| A3 interface consumed by another module changed | `grep -rn "WINDOW_HELP_SECTIONS\|MAP_KEYS_LINE\|MAP_REGION_ROW_FIELD_KEY" s19_app/` | `section_body_text`/`section_for`/`WindowHelpScreen`/`HELP_KEY_WINDOW` read `WINDOW_HELP_SECTIONS`; `LegendScreen` map branch reads the two legend constants — no signature change, so no consumer edits |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes (B1 symbols, B2 moved file, B3 goldens, B4 consumers, A3 interface) — no file moved, no interface changed, no golden re-pinned |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| stale help claims across the six rewritten sections | every stale phrase named by F-37/D7-26 | `grep -n` over `window_help.py` | 18 | 18 (all in the six rewritten entries) | 0 |
| stale README claims | every claim F-38/D0-9/D0-10/D0-11 names | `grep -n` over `README.md` | 11 | 11 | 0 |
| the md contract retirement (tc707/tc1802) | every test reading `help_sections.md` | `grep -rn "help_sections.md" tests/` | 3 nodes | 3 (re-bodied, names kept) | 0 |
| TC-607 scanned-corpus bound | every `tests/**/*.py` file | `find tests -name '*.py'` minus 4 excluded dirs | 252 | 1 (the bound) | 0 |

| Field | Value |
|---|---|
| **Correction population** | 4 corrections, each enumerated with its method before the first site was edited |

### Signed-balance test ledger

`post = base − deleted + added` → `71 covered + 3 not-testable = 71 − 2 + 3` ✓ reconciles after the records-only close (69 covered · 2 partial · 3 not-testable)

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` (E5) **PASS-WITH-NOTES**, 0 HIGH / 0 MAJOR, F1 … F8 closed by the corrective pass — `E5-code-review.md`. `security-reviewer` (E5) **Inc 14 without the SECURITY.md group: OK to ship; the group `BLOCK-UNTIL: E5-1`** (E5-1 MEDIUM, E5-2/E5-3/E5-4 INFO) — `E5-security.md`. `qa-reviewer` (E5 coverage audit): first audit 67/69 Coverage cells wrong; re-audit at `0bbb2c6` 8/33 re-checked cases still to change → the records-only close applies them — `E5-coverage-audit.md`. E3 design (code-free): `security-reviewer` **PASS-WITH-NOTES** (S-1 MEDIUM merge precondition, S-2 … S-8); the architect round 1 **FAIL** (6 MAJOR A-1 … A-6, 13 MINOR A-7 … A-19) → round 2 **PASS-WITH-NOTES** (all 7 blocking items closed; N-1 … N-3). Independent `tester` (E4) — the 72-node RED run on base is `red-01-tester-base.txt`. **There WAS a re-review (E3 round 2 and the E5 re-audit), because each round 1 blocked or found open records.** |

## 5 · Risks

- `SECURITY.md` names a private reporting channel that is still closed (`{"enabled":false}`); if the operator merges the file before enabling it, a reporter has no private route (E5-1). The hold-out group is the guard.
- The F4 key spelling is only half-reconciled (help writes `^K`, the key bar paints `^k`, the README sentence now quotes `^K`); the guide outside this slice keeps the bar's lower case — deferred to the batch-end doc pass.
- The guide captures ch06-05 / ch17-05 / ch19-01 / ch21-02 still show the old text; each carries the `(capture taken before 1.0.0: …)` note, and re-taking them needs the app + headless Edge (batch-end).
- Text written by this increment can be made stale by the open increments (Incs 4, 5, 6, 9, 10, 11, 12, 13) — the interface table I-1 … I-16 is the reconciliation plan.
- `test_b97_55` remains a load flake on a shared host (batch-97 Inc-6 precedent); Inc 14 changes no flow-execution code.

## 6 · Pending items / spec deviations

- **SECURITY.md hold-out group (N-2 / E5-1):** `SECURITY.md`, the three `test_r_doc_security_*` tests and the README `## Documentation` row (`:468`) are held out of the merge while `gh-pvr.txt` reads `{"enabled":false}`; the orchestrator removes exactly that group and re-checks it at the batch end with a new dated transcript reading `{"enabled":true}`.
- **Batch-end doc pass — key spelling (F4):** one spelling across help (`^K`) and the key bar / guide (`^k`); today only the README sentence was changed to `^K`.
- **Batch-end doc pass — guide captures (D-5 / BL-I14-5):** re-take ch06-05, ch17-05, ch19-01, ch21-02 and apply R-DOC-GUIDE.1/.2 to the other increments' findings (D-8).
- **Interface — Inc 4:** CHANGELOG `## 1.0.0` (a variant run resolves symbols against the project's A2L — Inc 4 appends one `###` line); DOSSIER marked set; README block (12) Execute scope.
- **Interface — Inc 5:** README block (5) Check Editor — owner of any change to where Write .chk.json writes (BL-I14-6).
- **Interface — Inc 6:** Workspace help step 5 and README blocks (4)/(13) (`patches/`/`checks/` homes, F-06); Checks help step 1; README `b` row (F-05).
- **Interface — Inc 9:** README block (8) chain-set report wording (F-45).
- **Interface — Inc 10:** Split / Join help steps 1–2; A2L help step 3 (F-07 scroll).
- **Interface — Inc 11:** A2L help steps 4–5 (F-21); Split / Join help step 2 (F-29).
- **Interface — Inc 12:** Reports help — an `esc` step means a named supersession of Help copy I14 and the tc707 copy node; Inc 12 asks the orchestrator (it does not own `window_help.py`).
- **Interface — Inc 13:** README block (9) "recomputes on every keystroke"; CRC help step 3 (F-24).
- **SVG snapshot tests (29):** `not-run` — `pytest-textual-snapshot` is not installed in `s19ci`; owed to the batch-end full suite.
- **Full suite:** owed at batch end (the branch runs here are the focused and importer sets only).
- **Backlog rows:** BL-I14-1 (Memory Map inspector subtitle), BL-I14-2 (`changes_file_notation` JSON fence), BL-I14-3 (D3-19 legend rows), BL-I14-4 (README test-count / CLI-equivalence claims), BL-I14-5 (guide captures), BL-I14-6 (Check Editor home split).

## 7 · Suggested next task

Merge the Inc 14 records and the 2 text-only source files (holding out the SECURITY.md group per N-2/E5-1); then close the batch with the batch-end doc pass (F4 spelling, D-5 captures, the other increments' guide passages) and the full suite + SVG snapshot run on the LAN host.

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2 source files (`legend.py`, `window_help.py`); reason in §2 |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b101_help_legend_docs.py` + re-bodied tc707/tc1802/AT-285 |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | n/a — 0 functions changed (3 constants) |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | `red-01-tester-base.txt` (56 failed, 16 passed) |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | 5 probes in §4 |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | PASS-WITH-NOTES, 0 HIGH, F1 … F8 (§4b) |
| 7 | No file from another lane touched | all | ✓ | no fork; no shared file |
| 8 | Frozen interfaces untouched | all | ✓ | `window_help.py` / `legend.py` are not in the frozen set (`_ENGINE_PATHS` guards passed in int-02) |
| 9 | Coverage claims verified on disk | all | ✓ | the `*_1_*` cases read the shipped files |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 Load-bearing emptiness |
| 11 | **Mutation verdicts** declared per arm | all | ✓ | 45 KILLED / 0 SURVIVED / 2 N/A, per-node in `E5-mutants.md` |
| 12 | **Instrument RED-proof** declared | all | ✓ | 3 instruments (§4) |
| 13 | **Correction population** declared | all | ✓ | 4 corrections (§4) |
| 14 | **Emitted-form assertion** declared | all | ✓ | 3 artifacts (§4) |
| 15 | **Independent review** names somebody | all | ✓ | `architect`, `security-reviewer`, `code-reviewer`, `qa-reviewer` (§4b) |
| 16 | **Evidence files** declared | all | ✓ | 59 transcripts with SHA-256 (§4) |
