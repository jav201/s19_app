# Inc 4 — validation (E5)

**Verdict: PASS-WITH-NOTES.** Documents resolve their symbol entries through the loaded A2L at all six session reads and through the project's A2L file in variant and report runs, with a lazy tag-name index that keeps a 1 000-entry × 220 040-tag read well inside its 1.0 s bound, and the headless entry point is deleted. No product code changed in the E5 corrective pass — every strengthened test passed on the Inc 4 code. All 17 mutants are killed, the 23 cases are all covered, and the review chain is green. The open notes are records-only (a routed environment failure, a cross-session review-file edit, and the full suite owed at batch end). Branch `b101-inc4` at `200cc69` plus the uncommitted E5 records and this file. Platform: the LAN Linux host for every run and timing (operator rule); no run on the Windows PC.

## Runs

| Run | Result | Evidence |
|---|---|---|
| E5 corrective, the new test file `-n 4 -m "not serial_timing"` | **22 passed** (the 22 non-timing nodes, listed by name in the transcript) | `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-01.txt` |
| E5 corrective, its serial lane (`-m serial_timing`, `-s`), host load 3.6 | **2 passed** (kept as a record; superseded by `e5c-05`) | `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-02.txt` |
| E5 corrective, every test file that imports `changes.io`, `change_service` or `variant_execution_service` (90 files, 12 chunks of 8, `-n 4 -m "not serial_timing"`) | **2 737 passed, 1 failed, 97 skipped, 1 xfailed** (2 836 nodes). The failure is `test_changes_file_notation_help::test_tc1802_…` (E-1, environment: reads an untracked, excluded prototype file; fails on base too; routed) | `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-03-00.txt` … `e5c-03-11.txt` |
| E5 corrective, the law guards (`test_id_registry`, `test_suite_hygiene`, `test_engine_unchanged`, `test_requirements_canon`, `test_tui_patch_editor_v2`, `test_checks_engine`, `test_tui_directionb`, `test_changes_schema`), `-n 4 -m "not serial_timing"` | **379 passed** | `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-04.txt` |
| E5 corrective, serial lane of the new file on a quiet host (load 1.34, no other pytest) | **2 passed** (the final R-CHG-SYM.13 timing measurements) | `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-05.txt` |
| E5 corrective, serial lane (`-m serial_timing`) over the 90 importer files plus `test_suite_hygiene`, `test_id_registry` | **53 passed, 2 skipped**; QC-TM 80 bounds, 0 under 20 % margin | `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-06.txt` |
| E5 corrective mutants M-16 and M-17, each applied, run, restored and hash-checked (`RESTORE_OK`) | **both KILLED** — M-16 (`symbol_index is None`, `io.py:904`): "a read with no declared A2L called the index builder 2 time(s), expected exactly 1"; M-17 (per-entry confirm returns without reading or replacing, `app.py:5529`): `(164,) != (254,)` | `.dev-flow/2026-11-01-batch-101/evidence/inc-4/e5c-mut16.txt`, `e5c-mut17.txt` |
| E4 integration baseline (the earlier GREEN the E5 pass re-verified) | int-26 serial lane 53 passed, 2 skipped; int-27 `-s -m serial_timing` 2 passed; int-28 final `-n 8 -m "not serial_timing"` **179 passed**, 0 failed | `.dev-flow/2026-11-01-batch-101/evidence/inc-4/int-26.txt`, `int-27.txt`, `int-28.txt` |

Every final E5 transcript prints the tree fingerprint `7f5b5b48049d1725` at start and end, the same as the local `git diff b7b77c4` — so the runs cover exactly the worktree bytes. The one failure in the whole E5 pass (`tc1802`) is environment, fails on base, and is routed.

## Mutant score

**17 / 17 KILLED, 0 survived.** M-1 … M-15 (the "Negative control" seeds, one per requirement row, run by the E5 mutant battery) plus M-16 and M-17 (the E5 corrective additions that close the code review's F1 and the coverage audit's C-1). Details: `E5-mutants.md` and `E5-corrective-notes.md`; transcripts `.dev-flow/2026-11-01-batch-101/evidence/inc-4/mut-00-base.txt`, `mut-01.txt` … `mut-15.txt`, `e5c-mut16.txt`, `e5c-mut17.txt`.

## Reviews

- **E3 design:** `architect` **PASS-WITH-NOTES** (A-1 HIGH, A-2 … A-4 MAJOR, A-5 … A-9 MINOR — all folded into the records by `E3-rulings.md` before E4) and `security-reviewer` **PASS-WITH-NOTES** (S4-1, S4-2 LOW, S4-3 … S4-9 INFO). The A-1 HIGH (the registry node the deletion makes RED) is discharged by the integration edit and `test_id_registry.py` in the targeted run.
- **E5 code review:** `code-reviewer` **PASS-WITH-NOTES**, 0 HIGH — F1–F3 MINOR (test strength) and F4–F5 NIT (records) closed by the corrective pass; SR-1 (the review-file citation seam) judged minimal and correct.
- **E5 security review:** `security-reviewer` **PASS-WITH-NOTES**, 0 HIGH — E5S4-1 LOW (record row) and E5S4-2 … 5 INFO; no new permission, trigger, action, sink or secret.
- **Coverage audit:** first audit changed 11 of 22 cases (4 full → partial) and added the owed row R-CHG-SYM.13/3; the re-audit at `200cc69` re-checked 21 of 23 cases: **23 cases, all covered, 0 partial, 0 gap**, 17/17 mutants killed, 0 black-box ATs owed, 24/24 cited nodes collect.

## Measured times (LAN Linux host, quiet, `e5c-05`)

- **R-CHG-SYM.13/1** — `parse_change_document`, 1 000 symbol entries × 220 040 tags, index built 1× per run: **0.173–0.181 s, 5/5** (bound 1.0 s, margin ≥ 81.9 %). The `e5c-02` record run (load 3.6) gave 0.180–0.188 s.
- **R-CHG-SYM.13/3** — the cost symbol resolution adds to the whole-document Edit JSON confirm: additions **0.422 / 0.290 / 0.021 / 0.008 / 0.351 s, max 0.422 s, 5/5** against `timing_bound(1.0)` (OR-2: min(2 × the E4 measured 0.622 s, 1.0 s)); margin ≥ 57.8 %.

## Cross-ownership edit

The D-1 deletion forced a seam across the parallel requirements re-write session: `docs/requirements/review/S9-ears-strict.md` (R-CHK-001 note and D9-7 text) and `docs/requirements/review/CODE-CHANGES.md` (D9-7 marked `done (batch-101 Inc 4)`) were reworded to drop the dead test name, because canon guard R-DOC-CANON.10 refuses a code-span citation of a test that no longer exists. Both edits were forwarded to the requirements session on 2026-11-05 for confirmation; `docs/requirements/history/` keeps the old name.

## Not run / owed

- **`tc1802`** fails on clean clones (it reads an untracked, excluded prototype file); it fails on base too and is routed to the backlog — **Inc 14 re-bodies it**.
- **The full suite** (all 3 000+ nodes in one lane) is owed at batch end; this increment ran its slice plus every importer and every law guard, in lanes, on the LAN Linux host.
- The E1 probe and E4/E5 timings set no threshold on the Windows PC (operator rule); all figures above are the Linux-host runs.

## Trace

`trace_check.py --req 01-requirements.md E1-slice.md --tests tests --base b7b77c4 --src s19_app` at close: `trace_check: 3 US, 6 active requirements (0 withdrawn), 0 gap(s)` (the one short evidence-path citation in this record was corrected to its full committed path; no EVID "not committed" gap remains).
