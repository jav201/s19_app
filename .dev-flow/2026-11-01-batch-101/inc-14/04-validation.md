# Inc 14 — validation (E5)

**Verdict: PASS-WITH-NOTES.** The help, legend, README, CHANGELOG and user-guide texts are true to the shipped app at head `0bbb2c6`; every mutation the negative-control column names is killed; no HIGH is open. **`SECURITY.md` is held out of the merge** while `.dev-flow/2026-11-01-batch-101/evidence/inc-14/gh-pvr.txt` reads `{"enabled":false}` (2026-11-05T23:42:44Z): under ruling A-6 + S-1 and addendum N-2, the hold-out group goes with it and is re-checked at the batch end. The rest of Inc 14 ships. Branch `b101-inc14` at `0bbb2c6` plus the uncommitted E5 records (this file, the re-audit section of `E5-coverage-audit.md`, `E5-mutants.md`, the 45 mutant transcripts and the re-audit edits of `02-test-cases.md`). No product file under `s19_app/` changed after E4; the 2 source files are text-only (`window_help.py`, `legend.py`). All runs: LAN Linux host (operator rule), conda env `s19ci`, Python 3.11.18.

## Runs

| Run | Result | Evidence |
|---|---|---|
| int-01 (E4 first run, focused set) | 6 failed, 227 passed, 3 skipped — all 6 in the tests (5) or the TC-607 registry bound (1) | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-01-first-run.txt` |
| int-02x (whole GREEN set, one run) | stopped by the integrator at ~31 of 40 min (host load); no summary | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-02x-combined-killed-at-timeout.txt` |
| int-02 (group A + law guards) | **505 passed, 3 skipped, 0 failed** | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-02-group-a-inc14-and-guards.txt` |
| int-03 (group B, importers) | 1 failed (TC-B97-55 load flake), 669 passed, 10 skipped | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-03-group-b-b97-b99-b100.txt` |
| int-04 (TC-B97-55 isolated ×3) | 2 passed × 3 | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-04-tc-b97-55-isolated-reruns.txt` |
| int-05 (group C) | 1 failed (harness `--basetemp`), 203 passed, 29 skipped | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-05-group-c-report-split-diff-snapshot.txt` |
| int-06 (snapshot rerun, `--basetemp` under `pytest-…`) | 4 passed, 29 skipped | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/int-06-snapshot-rerun-pytest-basetemp.txt` |
| int-07 (E5 reworked guards + supporting + C-4 files) | **1 failed**, 502 passed, 4 skipped — the failure is the hygiene redaction guard on a record line (E5-security.md quoted a shared Public-profile path), re-ran GREEN in int-07b | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-int-07-inc14-reworked-guards-supporting.txt` |
| int-07b (hygiene rerun after the record fix) | **65 passed** | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-int-07b-hygiene-rerun-after-record-fix.txt` |
| int-08 (importers, group B) | **670 passed, 10 skipped** | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-int-08-importers-b97-b99-b100.txt` |
| int-09 (importers, group C) | **274 passed** | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-int-09-importers-legend-report-split.txt` |
| RED on base (tester) | 56 failed, 16 passed (72 nodes) | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/red-01-tester-base.txt` |
| C-1 mutant proof (M1 Checks loses Hex Peek, M2 A2L `Goto`→`Go`) | RED on the strengthened test, GREEN on the pre-E5 probe; `app.py` diff empty after revert | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/e5c-c1-mutants-red-then-green.txt` |
| E5 `gh api` private-vulnerability-reporting | `{"enabled":false}` (exit 0) | `.dev-flow/2026-11-01-batch-101/evidence/inc-14/gh-pvr.txt` |

## Mutant score

**45 / 45 KILLED, 2 N/A.** Every product-text mutation the negative-control column names is caught by the test(s) its case row cites; 0 survived. The 2 N/A (M19, M24) are not product-text mutations: M19 is a behaviour change in `screens_directionb.py`, M24 a code-side flag already exercised by the in-test negative control of `test_at285`. Transcripts: `.dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-*.txt` (45 files, `mut-01` … `mut-47` minus M19/M24, which have no transcript). Table: `E5-mutants.md`.

## Reviews

- **E3 design:** `architect` round 1 **FAIL** (6 MAJOR A-1 … A-6, 13 MINOR A-7 … A-19) → round 2 **PASS-WITH-NOTES** (A-1 … A-6 and S-1 closed; addenda N-1 … N-3, plus INFO notes). `security-reviewer` **PASS-WITH-NOTES** (S-1 MEDIUM = the private channel not yet open; S-2 … S-5 LOW, S-6 … S-8 INFO). `E3-architect.md`, `E3-security.md`, `E3-rulings.md`.
- **E5 code review:** `code-reviewer` **PASS-WITH-NOTES**, no BLOCKER and no MAJOR — findings F1 … F8 (MINOR / NIT), each closed by the corrective pass (`E5-code-review.md`, `E5-corrective-notes.md` §2).
- **E5 security review:** `security-reviewer` — **Inc 14 without the SECURITY.md group: OK to ship (security lens); the SECURITY.md group: `BLOCK-UNTIL: E5-1`** (the reporting channel the policy names is still closed). No HIGH. Findings E5-1 (MEDIUM), E5-2/E5-3/E5-4 (INFO). No personal name, account name, host name, IP or e-mail address in any Inc 14 text (`E5-security.md`).
- **Coverage audit** (independent `qa-reviewer`): first audit found 67 of 69 cases' Coverage column wrong as written; re-audit at `0bbb2c6` re-checked 33 changed/new cases and closed the nine clauses, the `?`/`k` black-box checks and the load-path notes. Re-audit totals before the records-only close: covered **66** · partial **5** · not-testable **3**. After the records-only corrections (§Test-case totals): covered **69** · partial **2** · not-testable **3**.

## Test-case totals

`02-test-cases.md`: **74 cases** over 27 requirement rows (help 27, legend 4, README 7, security 5, release notes 17, guide 14). After the E5 re-audit's records-only corrections (GUIDE.1/1, /4, /7, /8 cite the 1/12 node; R-WHELP.7/2 and R-DOC-GUIDE.1/9 `partial`; SECURITY.2/1 and README.4/2's `SECURITY.md` entry tagged into the hold-out group): **69 `covered`, 2 `partial`, 3 `not-testable`**. Results: 71 `verified (linux, int-07)`, 1 `failed` (R-DOC-SECURITY.1/2, the setting is off), 2 `not_run` (the two not-testable cases that are not the E5 evidence item).

## Hold-out group (SECURITY.md, ruling N-2 / E5-1)

Exactly, held out together and re-checked at the batch end:
- `SECURITY.md`;
- the three tests `test_r_doc_security_1_1_policy_names_private_path`, `test_r_doc_security_2_1_supported_versions`, `test_r_doc_security_1_3_readme_links_the_policy` (all in `tests/test_b101_help_legend_docs.py`);
- the README `## Documentation` row that links `SECURITY.md` (`README.md:468`; it was `:429` before the E5 rewrap, E5 C-9).

`test_r_doc_readme_4_2_linked_documents_exist` **stays**: after the row is held out it still checks the CHANGELOG link. R-DOC-README.4/2's `SECURITY.md` entry is conditional on the group (re-audit R.2 #5).

## Not run / owed

- **SVG snapshot tests (29):** `not-run` on the LAN host — `pytest-textual-snapshot` is not installed in `s19ci` (E4 §5). A text scan of `tests/__snapshots__/` finds neither the old nor the new legend lines, so no baseline is expected to move.
- **Full suite:** owed at batch end (the branch runs here are the focused and importer sets only).
- **R-DOC-SECURITY.1/2** re-run at batch end: a new dated `gh api` transcript reading `{"enabled":true}` is the precondition for merging the hold-out group (E5-3).
- **F4 key spelling** outside the slice (help `^K` / README bar `^k`) and the guide captures (D-5) go to the batch-end doc pass.

## Trace check

`trace_check.py --req 01-requirements.md E1-slice.md --tests tests --base b7b77c4 --src s19_app`

```
EVID   .dev-flow/2026-11-01-batch-101/inc-14/04-validation.md cites .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-*.txt, which is not committed
EVID   .dev-flow/2026-11-01-batch-101/inc-14/04-validation.md cites .dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-*.txt, which is not committed
trace_check: 6 US, 36 active requirements (0 withdrawn), 2 gap(s)
```

The 2 EVID gaps are the mutant transcripts (`.dev-flow/2026-11-01-batch-101/evidence/inc-14/mut-*.txt`, 45 files), which are uncommitted — expected: this record and the mutant battery are written at E5 close and are committed by the orchestrator with the other E5 records. No US, CASE, TEST, SLICE, EVID-record or CANON gap.

## Addendum (orchestrator, 2026-11-06)

The operator asked to enable GitHub private vulnerability reporting; it was enabled with `gh api -X PUT` and now reads `{"enabled":true}` (`evidence/inc-14/gh-pvr-2.txt`). E5-1 is closed, R-DOC-SECURITY.1/2 is verified, and the hold-out no longer applies: SECURITY.md, its three tests and README row 468 merge with Inc 14.

## Addendum 2 (orchestrator, 2026-11-06)

The merge verification on LAN host 2 (main + Inc 11 + Inc 14) found the law guard `tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` RED: `tests/test_b101_help_legend_docs.py:1153/1160` passed a subscript (`rows[2]`) to `pilot.click`/`pilot.double_click`, a form the census refuses. Fix: the target is bound to a name first (`target_row = rows[2]`), no assertion changed; `tests/test_address_census.py` + the Inc 14 test file: 92 passed. Cause: the Inc 14 runs did not include the address-census law guard (it is not named in the repo's law-guard list the briefs cited) — recorded for the batch-end battery.
