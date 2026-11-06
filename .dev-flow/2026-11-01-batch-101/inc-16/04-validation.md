# Inc 16 — validation (E5)

**Verdict: PASS-WITH-NOTES.** A documentation-hygiene increment: stale, dead and duplicate documents are corrected, archived or removed, and no product code changed (the two source files touched are comment-only, and `REQ-crc.md` is a document deleted from the package tree). All 35 mutants are killed, all 53 cases read `covered`/`verified`, and the review chain is green — the architect FAILED E3 round 1 (6 MAJOR) and passed round 2 PASS-WITH-NOTES; the E5 code reviewer passed PASS-WITH-NOTES carrying the security lens (there is no separate security reviewer for a docs increment); the coverage audit's 5.8 % judgment changes were corrected and the re-audit is PASS-WITH-NOTES with no mark changed. The open notes are records-only. Branch `b101-inc16` at `739a2128` plus the uncommitted E5 records and this file. Platform: the LAN Linux host for every run (operator rule); no run on the Windows PC.

## Runs

| Run | Result | Evidence |
|---|---|---|
| E4 integration, guards + laws (`-n 8 -m "not serial_timing"`) | **156 passed, 0 failed** (77 s) | `.dev-flow/2026-11-01-batch-101/evidence/inc-16/int-01.txt` |
| E4 integration, edited files and readers | **978 passed, 2 failed, 11 skipped** (14 min); the 2 failures are `test_tui_snapshot.py` density snapshots that fail identically on base (`int-05`) | `.dev-flow/2026-11-01-batch-101/evidence/inc-16/int-02.txt` |
| E4 integration, CLI forms (I-1) | `<command> <file>` exit 0 ×3; `<file> <command>` exit 2 ×2 (argparse `invalid choice`) | `.dev-flow/2026-11-01-batch-101/evidence/inc-16/int-03.txt` |
| E4 integration, counts + negative controls | 5/5 killed; `scanned_test_files()` = 263 | `.dev-flow/2026-11-01-batch-101/evidence/inc-16/int-04.txt` |
| E4 integration, base differential | 2 failed (the same two snapshot nodes on the untouched base) | `.dev-flow/2026-11-01-batch-101/evidence/inc-16/int-05.txt` |
| E4 integration, final tree guards | **228 passed, 0 failed** (114 s) | `.dev-flow/2026-11-01-batch-101/evidence/inc-16/int-06.txt` |
| E4 independent tester, RED-on-base | 38 of 45 nodes RED | `.dev-flow/2026-11-01-batch-101/evidence/inc-16/red-01-tester-base.txt` |
| E5 mutant battery (DeepSeek) | **35/35 KILLED**; baseline 46 passed, 0 failed | `.dev-flow/2026-11-01-batch-101/evidence/inc-16/mut-01.txt` … `mut-35.txt` |
| E5 corrective controls | `e5c-01` … `e5c-04` 22/22 as expected; `e5c-05` … `e5c-08` 4/4 PASS; `e5c-09` 4/4 FAIL as expected | `.dev-flow/2026-11-01-batch-101/evidence/inc-16/e5c-01.txt` … `e5c-09.txt` |
| E5 corrective final run (`-n 8 -m "not serial_timing"`) | **192 passed, 0 failed** (113 s); 193 collected, 1 deselected by the marker (the serial-lane node) | `.dev-flow/2026-11-01-batch-101/evidence/inc-16/e5c-10.txt` |

`e5c-10` ran on branch `b101-inc16` at commit `b843fc6` plus the uncommitted E5 corrective edits (patch sha256 `8340ce1de8464615`); the record cites it by that commit hash (E5-rulings RA-2).

## Mutant score

**35 / 35 KILLED, 0 survived** (DeepSeek, `E5-mutants.md`), plus the corrective controls of the guards changed or added at E5: `e5c-01` … `e5c-04` 22/22 as expected and the E5-T oracles' own negative controls `e5c-09` 4/4 FAIL as expected. Baseline before any mutant: 46 passed, 0 failed. Details and first assertion lines: `E5-mutants.md`; transcripts `.dev-flow/2026-11-01-batch-101/evidence/inc-16/mut-01.txt` … `mut-35.txt`.

## Reviews

- **E3 design (`architect`, security lens included):** round 1 **FAIL** — 6 MAJOR (A16-1 … A16-6), 10 MINOR, no BLOCKER/HIGH; one correction pass, round 2 **PASS-WITH-NOTES** (A16-1 … A16-6 closed; notes N-1 … N-3 to E4).
- **E5 code review (`code-reviewer`):** **PASS-WITH-NOTES** — 0 BLOCKER / 0 HIGH / 0 MAJOR, 5 MINOR (F-1 … F-5), 6 NIT (F-6 … F-11). It carried the security lens; there is no separate security reviewer for a docs increment. Security clean (C-1 … C-5: no identity leak in the diff; the two comment-only source files are byte-identical by token stream and masked AST).
- **Coverage audit (`qa-reviewer`):** first audit — the record held E1 placeholders; 5 of 52 cases had judgment changes, 3 of them full/partial or coverage marks (**5.8 %**). Corrective pass C-1 … C-10; **re-audit PASS-WITH-NOTES, no mark changed** (RA-1 keeps ARCH.5/2 `full`/`covered`; RA-2 records the test-cases header executor note).

## Integration finding

**I-1** — the CLI examples in `CLAUDE.md` did not run as written. R-DOC-DEV.2 prescribed `<file> <command>`, which argparse rejects (`invalid choice: '…firmware.s19'`, exit 2), because `s19_app/cli.py` gives each sub-parser its own `file` positional. The requirement, the doc and the test all agreed with each other and were wrong against the code; all three corrected to `python -m s19_app.cli <command> <file>`. DEV.2/1 kills both wrong forms (M-1, M-2, `int-04`).

## Document change map

| Action | Count |
|---|---|
| edited | 9 documents (plus 2 comment-only source files, 8 comment-only test files, 1 widened guard) |
| created | 2 (1 archive document + 1 test file) |
| moved (`git mv`) | 3 |
| removed (`git rm`) | 37 (4 files + the 33-file `.fast-dev-flow/` folder) |
| source files under `s19_app/` | 3 (2 comment-only, 1 Markdown deleted) |

(`E1-slice.md` §5; `codewire/graph-inc16.md`.)

## Not run / owed

- **The full suite at merge time, including the serial lane** — this increment ran its guards, every edited/reader file, the law guards and the final guard run in the non-serial lane, but not all nodes in one lane; the one serial-lane node (`tests/test_suite_hygiene.py::test_r_tst_020_shared_wait_is_bounded_by_the_wall_clock`) is owed at merge.
- **C-10 backlog redaction row** — the redaction pass over the 48 older `.dev-flow/` records holding a drive path and the 14 holding the local account name is one `BACKLOG-CODE.md` row; no old record is redacted here.
- **Inc 9 docstring row I-7** — `flow_screens.py`'s stale docstring citation is routed to Inc 9 (which owns the file); ARCH.4/2 no longer reads the docstring.
- **Root exposure F-9** — the `root`-account false RED in `tests/test_suite_hygiene.py`'s helper copy is owned by Inc 15; this increment fixed only its own copy in `tests/test_b101_doc_hygiene.py`.
- **ARCH.5/2's three own clauses** have no cited negative control of their own (RA-1) — recorded as owed and as a backlog line.

## Trace

`trace_check.py --req 01-requirements.md E1-slice.md --tests tests --base c2cba35 --src s19_app` at close: `trace_check: 3 US, 32 active requirements (0 withdrawn), 1 gap(s)` — the one gap is TEST `R-DOC-ARCHIVE.2` (an increment-local history fact whose cases are E5 transcripts, not a standing test; by design, D-1/D-10). No EVID "not committed" gap remains: the short `…/` citations of the first run were corrected to the full committed paths under `.dev-flow/2026-11-01-batch-101/evidence/inc-16/`, and this record plus the increment packet are uncommitted working-tree files, not evidence paths.
