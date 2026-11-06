# Inc 5 — validation (E5)

**Verdict: PASS-WITH-NOTES.** The CRC Designer refreshes its coverage after the three in-place writes into the loaded image (Patch Editor apply, save-back, Save project commit), and the Check Editor keeps the operator's picks, resolves picked entries to their named parameters from the loaded A2L, keeps a spec's declared bytes keyed by (name, address, size), demotes a moved/renamed/resized parameter into an unlabelled memory row at the spec entry's own address, and clears its validation results after an in-place write. Every new node is RED on base for a behavioural reason and GREEN on the integrated tree; the 24-mutant DeepSeek battery is 24/24 KILLED, the six corrective mutants M25–M30 and the 12 security-reviewer mutants are all killed, and the review chain ends green (E3 round-2 security PASS-WITH-NOTES, E5 code review PASS-WITH-NOTES, E5 security re-review closed, coverage re-audit PASS). The open notes are records-only. Branch `b101-inc5` at `87b429af` plus the uncommitted E5 records and this file; base `c2cba35`. Platform: the LAN Linux host for every run and timing (operator rule); nothing that imports `s19_app` ran on the Windows PC.

## Runs

| Run | Result | Evidence |
|---|---|---|
| E1 confirmation pilot (base `c2cba35`, detached worktree) | D-4 reproduced: after the apply the CRC Designer still shows `concat: 0x9C5BCBBD` (0 recomputes) while `zlib.crc32` of the post-apply bytes is `0x08DAAFB7`; F-26 not reproduced; F-27 and D9-11 reproduced | `.dev-flow/2026-11-01-batch-101/inc-5/evidence-e1/i5e1-pilot-transcript.txt` |
| Tester 1 RED on base (designer writes) | 8 failed, 2 passed (the declared standing guards) | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/red-01-tester1-base.txt` |
| Tester 2 RED on base (Check Editor + symbol-reads node) | 21 failed, 6 passed (the declared standing guards) | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/red-01-tester2-base.txt` |
| E4 integration int-01 | **58 passed** (the two new files + the re-pinned symbol-reads node) | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/int-01.txt` |
| E4 integration int-02 | QC-BC set, 51 files: 2 failed, **2428 passed**, 107 skipped, 1 xfailed (the 2 failures are the batch's known ones, int-03) | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/int-02.txt` |
| E4 integration int-03 | the 2 int-02 failures on base: 2 failed, same assertions | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/int-03.txt` |
| E4 integration int-04 | the 24 other importers of `screens_directionb` / `crc_designer_view`: 2 failed, **488 passed** (the 2 failures are known, int-05) | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/int-04.txt` |
| E4 integration int-05 | the 2 int-04 failures on base: 2 failed, same | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/int-05.txt` |
| E4 integration int-06 | law guards: **117 passed** | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/int-06.txt` |
| E4 integration int-07 | `-m serial_timing`, serial, over all 85 files: **58 passed**, 2 skipped, 3201 deselected; `QC-TM: 84 bounds, 0 under 20 % margin` | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/int-07.txt` |
| E4 integration int-08 | `-rs` on the slice's closest modules: **399 passed**, 4 skipped (Windows-only arms) | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/int-08.txt` |
| E4 integration int-09 | `-m serial_timing -rs`, serial: **52 passed**, 2 skipped | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/int-09.txt` |
| E5 corrective e5c-01 | RED on base: the 10 E5 nodes, **9 failed, 1 passed** (002.5/9, the declared standing guard); each failure an assertion on the targeted defect | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/e5c-01.txt` |
| E5 corrective e5c-02 | GREEN: `D` + `C` + symbol-reads, `-n 8 -m "not serial_timing"`: **68 passed** | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/e5c-02.txt` |
| E5 corrective e5c-03, e5c-04 | Check Editor cases, runs 2 and 3 of 3: **33 passed**, **33 passed** | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/e5c-03.txt`, `e5c-04.txt` |
| E5 corrective e5c-05 … e5c-10 | mutants M25 … M30 in a copy of the GREEN tree: **6/6 KILLED** | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/e5c-05.txt` … `e5c-10.txt` |
| E5 corrective e5c-11 | law guards (`test_address_census`, `test_suite_hygiene`, `test_id_registry`, `test_engine_unchanged`, `test_docs_canon`): **103 passed** | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/e5c-11.txt` |
| E5 corrective e5c-12 | `-m serial_timing`, serial, over `D`, `C`, symbol-reads: **2 passed** | `.dev-flow/2026-11-01-batch-101/evidence/inc-5/e5c-12.txt` |

The four E4 integration failures (int-02, int-04) are the batch's known failures, identical on base `c2cba35` (int-03, int-05): `test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact`, `test_at_056e_a2b_diff_report_byte_identical_despite_selection`, and the two `test_tc016s_density_layout_snapshot[patch-comfortable-*]` arms.

## Mutant score

- **DeepSeek battery at `8fc3cd3`: 24 / 24 KILLED, 0 SURVIVED, 0 BAD** (M1–M24, one per requirement row's negative control plus the E3 addenda; transcripts `.dev-flow/2026-11-01-batch-101/evidence/inc-5/mut-01.txt` … `mut-24.txt`). Details: `E5-mutants.md`.
- **Corrective additions: M25–M30, 6 / 6 KILLED** (M25 the demoted row leaving out its expected bytes; M26–M28 the deciding controls for 010/1, 025/1, 027/1; M29 the helper not clearing the Check Editor; M30 the save-back handler swallowing the error). Details: `E5-corrective-notes.md`; transcripts `.dev-flow/2026-11-01-batch-101/evidence/inc-5/e5c-05.txt` … `e5c-10.txt`.
- **Security-reviewer subset: 12 / 12 KILLED** (M24, M22, M23, M20, M21, M19, M1, M5, M7, M2, M6, M3 — every E3 mitigation's named control turned RED for the stated reason), run in the first E5 security review (`E5-security.md`).

## Reviews

- **E3 design (code-free):** `architect` **FAIL** (0 BLOCKER, 0 HIGH, 1 MAJOR A-1, 5 MINOR) and `security-reviewer` **FAIL — BLOCK-UNTIL SEC5-1** (1 HIGH, 2 MAJOR, 2 MINOR, 1 INFO). Both approve the D-4 half and the in-place-write census. The corrective applied SEC5-1 … SEC5-6 / A-1 … A-6 through `E3-rulings.md`; round 2 re-checked SEC5-1, SEC5-2, SEC5-3 and A-1 only: **PASS-WITH-NOTES**, with R2-1 (MINOR) as a backlog row.
- **E5 code review:** `code-reviewer` **PASS-WITH-NOTES**, 0 HIGH — F1 MAJOR design-gap (the "expected bytes" clause of R-CHKED-056 had no discriminating case), F2–F3 MINOR, F4–F6 NIT, all folded by the corrective pass C-1 … C-11.
- **E5 security review:** `security-reviewer` **PASS-WITH-NOTES**, HIGH 0 — E5-S1 MEDIUM design-gap (stale validation results after an in-place write), folded in as the new row **R-CHKED-057** through C-10; E5-S2/S3 INFO. Every E3 mitigation `executed` and `approved` in code.
- **Coverage audit:** first audit changed **10 of 34 = 29.4 %** of the cases' marks/coverage and named the four owed black-box ATs; the corrective pass (C-1 … C-11) landed them. **Security re-review closed** (E5-S1 and code-review F1 `executed` · `approved`, HIGH 0, MEDIUM 0) and **re-audit PASS, 0 marks to change** — 40 cases, 36 `covered`, 4 `partial` (002.5/6 and 002.5/9: fault injected; 041.3/5 and 041.3/6: panel seam), 0 gap.

## Admitted visible changes

`E1-rulings.md` §1 items (5)–(7), and R-CHKED-057's cleared state — no layout change; values that were stale or wrong become right:

- **(5)** Write after a spec pick no longer re-baselines a field loaded from a spec from the image: it writes the spec's bytes again. To re-baseline one field, exclude and include the parameter, or remove and add the memory row.
- **(6)** A rewritten spec lists its parameter entries first, then its memory rows, so picking and rewriting a spec whose parameter and plain-address entries are interleaved reorders its entries, its Validate rows and its `## Checks` numbering.
- **(7)** When a newly loaded A2L lists a parameter loaded from a spec at another address or with another byte count, or no longer lists it, that field shows as an unlabelled `▪` memory row at the spec's address, and the parameter's ledger row is not `✓`.
- **R-CHKED-057's cleared state** (new at E5): after an in-place write the Check Editor's validation results clear to the card's mount state — 0 verdict rows and the status line exactly `Validate compares fields to the image`, with no painted line reading `validation complete` or ending `-> pass`. A following Validate still reports the drift (e.g. `0x0-0x0 expected [6C] actual [93] -> fail`).

## Owed

- **E5-rulings RA-1 … RA-5** (residuals, none blocking): RA-1 M1–M24 ran at `8fc3cd3` before the corrective and carry over by reasoning — the batch-end battery re-runs the mutant table on the merged tree; RA-2 mutant transcripts end in `Files … differ`, not the mutant text — future units print the diff; RA-3 R-CHKED-041.2/4 and 041.3/1 have no executed control of their own and 010/4's base failure hits another defect — backlog line for the next Check Editor increment; RA-4 AT-I5-4 proves the save-back confirm is reachable by keys, not that the clipped row is visible — backlog (KF-101 family); RA-5 refused/raising paths reach R-CHKED-057 only through the shared hook (RR-2), and R-CHKED-056's Base column is refreshed by this close record (RR-3) — done in STEP 1.
- **The merge-time full suite** — this increment ran its slice, the QC-BC importers, the law guards and the serial lanes, but not all nodes in one lane.
- **The Inc 10 LAN check** of the A2L explorer's value column and the Split/Join window after an in-place write (D-4 / SEC5-6), before Inc 10's E1.
- **The canon-fold wording of R-CRC-PREVIEW-002.5/8** — the threshold still says "the entry's address edited to `0x9000`"; the product route is Remove of `0x8003` and Add of `0x9000` (I-D3), so the precondition should read "the `0x8003` entry removed and a `0x9000` entry added" at the canon fold.

## Trace

`trace_check.py --req 01-requirements.md E1-slice.md --tests tests --base c2cba35 --src s19_app` at close: `trace_check: 3 US, 13 active requirements (1 withdrawn), 0 gap(s)`. The evidence citations in this record were written with their full committed paths (`.dev-flow/2026-11-01-batch-101/evidence/inc-5/…`) so no EVID "not committed" gap remains; `04-validation.md` and `03-increments/increment-005.md` are the two new records of this unit and are uncommitted until the orchestrator commits them.
