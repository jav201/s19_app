# Inc 13 — validation (E5)

**Verdict: PASS-WITH-NOTES.** The CRC Designer and the Split/Join preview are responsive at the 10 MB demo image, with the conflict-first state line ruled in by C-1. No HIGH or MAJOR is open: the one MAJOR (E4-F1 / E5-CR-1, `_state_text` painting the GUARD chip over the clobber line) was fixed by the E5 corrective pass and re-reviewed PASS. Two LOW security findings are routed to the backlog; one flake (`test_tc_b97_69`) is in the backlog with no established cause. Branch `b101-inc13` at `3e01603` plus the uncommitted re-review / re-audit sections and this record. Platform: E4 runs on **LAN Linux host 2** (16 cores, env `s19ci`); the E5 corrective and mutant runs on the **LAN Linux host** (the laptop; LAN host 2 was not answering ssh). Nothing ran on the Windows PC.

## Runs

| Run | Result | Evidence |
|---|---|---|
| E4 lane 1, before the integration fixes (`-n 12 -m "not serial_timing"`) | 3 failed, 801 passed, 16 skipped | `../evidence/inc-13/int-lane1-r1.txt` |
| E4 lane 1, after the fixes | **804 passed, 16 skipped**, 0 failed | `../evidence/inc-13/int-lane1-r2.txt` |
| E4 the three run-1 failures alone, after the fixes | 14 passed | `../evidence/inc-13/int-probe-r1.txt` |
| E4 D-2 AST check + control (`-rA`) | 2 PASSED, not skipped (N-5) | `../evidence/inc-13/int-ast-r1.txt` |
| E4 serial lane (`-m serial_timing`), 3 runs alone | 4 passed each run; 0 bounds under 20 % margin | `../evidence/inc-13/int-serial-r1.txt` … `-r3.txt` |
| E4 tester RED on base | 15 Designer nodes + 4 timing arms RED for behavioural reasons; GREEN-by-design nodes pin unchanged behaviour | `../evidence/inc-13/red-01-tester-base.txt` |
| E5 mutant battery (LAN Linux host 2) | 24 KILLED / 25; M-12 SURVIVED (equivalent); R-SEG-PREV.7-NC N/A (blocked by E4-F1) | `../evidence/inc-13/mut-M-1.txt` … `mut-M-25.txt`, `mut-M-12.txt` |
| E5 corrective C-1 RED (before the `_state_text` fix) | 2 failed, 1 passed — both new nodes fail on the state-line equality alone | `../evidence/inc-13/e5c-c1-red.txt` |
| E5 corrective C-1 GREEN | 108 passed (band file, `test_segment_split_window.py`, `test_b97_key_bar.py`) | `../evidence/inc-13/e5c-c1-green.txt` |
| E5 corrective CR-3 RED / GREEN | RED: `TypeError: unsupported format string passed to NoneType.__format__`; GREEN: 4 passed | `../evidence/inc-13/e5c-cr3-red.txt`, `../evidence/inc-13/e5c-cr3-green-and-ats.txt` |
| E5 final lane (`-n 4 -m "not serial_timing"`) | **818 passed, 1 failed** (`test_tc_b97_69`, the routed flake), 16 skipped | `../evidence/inc-13/e5c-lane1.txt` |
| E5 serial lane, 5 runs alone (`-m serial_timing`) | 4 timing arms × 5 runs: **20/20 pass**, 0 margins under 20 % | `../evidence/inc-13/e5c-serial-r1.txt` … `-r5.txt` |
| E5 D-2 AST check (`-rA`) | 3 PASSED, not skipped | `../evidence/inc-13/e5c-ast.txt` |
| E5 `test_tc_b97_69` re-run alone, 3/3 | passes 3/3 (flake under load) | `../evidence/inc-13/e5c-b97-69-r1.txt` … `-r3.txt` |
| E5 corrective negative controls (C-1, C-2, CR-4, six surfaces, AT M-2 / M-7, Split/Join ATs) | each KILLED | `../evidence/inc-13/e5c-mut-NC-*.txt`, `../evidence/inc-13/e5c-split-join-ats.txt` |

## Mutant score

**24/25 KILLED** (96 %). The survivor **M-12** (dropping the adjacent-run merge in `_conflict_marks`) is classified *equivalent*: `build_plan` hands the marks only to `_sweep`, which coalesces adjacent equal blocks, so every plan field is byte-identical with or without the merge — dropped from R-SEG-PREV.2/2's controls by ruling C-5. Excluding the equivalent, the effective score is 24/24. The **R-SEG-PREV.7 negative control** (census taken from the merged blocks' count instead of their sizes) was **N/A** at the first E5 pass because E4-F1 hid the clobber line; after the C-1 `_state_text` fix it was run and **KILLED** by the F-23 clobber node, the priority node and TC-710 — `../evidence/inc-13/e5c-mut-NC-SEG-PREV-7.txt`. Details and per-mutant transcripts: `E5-mutants.md` (incl. the corrective-pass addendum).

## Reviews

- **E3 design (code-free):** `architect` round 1 **FAIL** (0 BLOCKER, 0 HIGH, 2 MAJOR A-1/A-2 in the test records, 6 MINOR; the product design was approved) → round 2 **PASS-WITH-NOTES** (A-1, A-2, SEC-1 closed; SEC-2 sound with the binding round-2 addendum fixing the coverage cap at **16 777 216 bytes (16 MiB)** and the E4 addenda N-1 … N-5). `security-reviewer` **PASS-WITH-NOTES** (MEDIUM SEC-1 … SEC-3, LOW SEC-4 … SEC-7, INFO SEC-8 … SEC-10; no HIGH). — `E3-architect.md`, `E3-security.md`, `E3-rulings.md`.
- **E5 code review:** `code-reviewer` **PASS-WITH-NOTES** (E5-CR-1 = E4-F1 MAJOR design-gap, recommended for the corrective pass; CR-2 MINOR; CR-3 … CR-5 NIT) → **re-review PASS** at `3e01603`: E5-CR-1 closed on the diff (branch order matches canon R-SEG-PREV.7 / .8; RED fails for the right reason in `e5c-c1-red`), CR-3/CR-4/CR-5 closed; two LOW notes (RR-1 pre-existing unreachable, RR-2 records for the requirements session). — `E5-code-review.md` §Re-review.
- **E5 security (implemented, probed):** `security-reviewer` **PASS-WITH-NOTES** — 0 HIGH, 0 MEDIUM, LOW 2 (F-1, F-2), INFO 3 (F-3 … F-5); every ruled-in E3 mitigation `executed` and `approved` by probe; F-1 and F-3 routed to the backlog, F-2 accepted (C-8). — `E5-security.md`.
- **Coverage audit (E5):** `qa-reviewer` first audit changed 17 of 39 cases (43.6 %) by judgment; **re-audit** at `3e01603` closed every §1–§5 issue except two re-checked cases (001.2.1/3 and 007.3/2, below) and two wording notes (R-SEG-PREV.20/1 objective, the stale cap at `E1-rulings.md` line 24). — `E5-coverage-audit.md` §Re-audit.

## Test-case totals

`02-test-cases.md`: **52 cases** (39 from E1/E3 + 13 E5c). Final totals after the re-audit: **covered 49, partial 3, gap 0, result 52 pass**. The three partials: R-CRC-DESIGNER-001.2.2/3 (reads the constant, not the wall clock), R-CRC-DESIGNER-001.2.1/3 and R-CRC-DESIGNER-007.3/2 (re-audit issues 1 and 2: each node's wait spans the injected 10 s quiet time, so M-1 / M-5 / M-6 would not turn it RED). Cited node ids that do not collect: 0 (191 collected).

## Measured times (serial lane, 5 runs, alone among this session's runs; `report_margin`)

The host was not quiet — another session's `-n 4` lane ran throughout (load 3.7–4.6). The margins hold anyway; each run reports `QC-TM: 4 bounds, 0 under 20 % margin`.

| Case | Bound | r1 | r2 | r3 | r4 | r5 | Worst margin |
|---|---|---|---|---|---|---|---|
| R-CRC-PREVIEW-002.2/1 (Join gaps change) | 3.0 s | 1.839 | 1.630 | 1.870 | 1.634 | 1.391 | 37.7 % |
| R-CRC-PREVIEW-002.3/1 (template load) | 3.0 s | 1.060 | 1.053 | 1.269 | 1.049 | 1.657 | 44.8 % |
| R-CRC-PREVIEW-002.4/1 (Ranges edit, after the quiet time) | 3.0 s | 1.401 | 1.671 | 1.208 | 1.200 | 1.213 | 44.3 % |
| R-SEG-PREV.20/1 (`g`, F-23 Split/Join scene) | 2.5 s | 0.884 | 0.946 | 0.794 | 0.689 | 0.772 | 62.2 % |

## Trace check

`trace_check.py --req 01-requirements.md E1-slice.md --tests tests --base b7b77c4 --src s19_app` (run at close): **3 US, 24 active requirements (1 withdrawn), 4 gap(s)**. All four are TEST gaps — R-CRC-PREVIEW-001.4, .5, .6 and .7 are not named by their own id (nor by a TC/AT id they list) under `tests/`: their cases cite the shared matrix node `test_r_crc_preview_001_2_coverage_field_state_matrix` (whose docstring writes the dotted range "001.2 .. 001.8") plus two existing generic nodes, none of which carries a `.4` … `.7` token the checker can read. No EVID gap: the 54 evidence transcripts cited above are committed. No SLICE, CASE, US or CANON gap.

## Not run / owed

- **The full suite at batch end.** The E5 lane ran the slice-covering set (the 3 new test files, the edited modules, every module that imports the three slice files, `test_id_registry.py`, `test_suite_hygiene.py` and the law guards), not the whole battery.
- **`test_tc_b97_69_page_keys_do_nothing_where_disabled`** — the "A2L loaded did not settle" flake: failed once under load 11–12, passed 3/3 alone; cause not established. Routed to `BACKLOG-CODE.md`.
- **Requirements-session records still describe the old state-line order.** `docs/requirements/review/S17-ears-strict.md:279` ("Partly: a guard file hides it") and `CODE-CHANGES.md` D17-27 predate the C-1 fix; the notice half of D17-27 (R-SEG-EXP.3) stays open. For the requirements session, not this record.
- The serial runs were not on a quiet host (disclosed above; C-3 asked for one, and a pass under load is conservative for an upper bound).
- Nothing was pushed; the records here are uncommitted and left for the orchestrator to commit.

## Addendum (orchestrator, 2026-11-06)

`trace_check --req inc-13/01-requirements.md inc-13/E1-slice.md --tests tests --base b7b77c4 --src s19_app`: `trace_check: 3 US, 24 active requirements (1 withdrawn), 0 gap(s)` after the orchestrator spelled out the abbreviated requirement ids (".4, .6, .7") in the docstring of `tests/test_b101_designer_recompute.py::test_r_crc_preview_001_2_coverage_field_state_matrix` (docstring text only). The record run above reported 4 TEST gaps for R-CRC-PREVIEW-001.4…001.7 for that reason.
