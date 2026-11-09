# Inc 11 E5 independent coverage re-audit: FAIL

## Verdict

**Static coverage: FAIL.** The 136 original audit IDs now classify as **98 full, 37 partial, 0 gap, and 1 false-premise**. The per-ID nodes, assertions, residual reasons, and transcript paths are in `evidence-e5/coverage-completion-report.md`.

This was a static on-disk review. No tests were run on Windows, no product/test/matrix files were edited, and no result cell was changed. The two application ATs are outside the 136-ID scope.

**Runtime/validation is also not green.** `evidence-e5/coverage-and-e5-green.txt:1-5` proves a scratch-package C+E run with 136 passed and exit 0, but `evidence-e5/coverage-perf.txt:7-37` has 6 passed/1 failed and exit 1. E5 must not be declared globally green.

## Findings

### HIGH — 37 requirement cases still have partial static coverage

The supplemental module closes many observables, but the following IDs retain the concrete gaps detailed in the completion report:

- Missing zero-state, exact-line, complete-value, or one-word assertions: **R-A2L-READ.55/2; R-A2L-READ.55/3; R-A2L-READ.55/4; R-A2L-READ.56/1; R-A2L-READ.56/2; R-A2L-READ.66/3; R-A2L-001.3.2/4; R-A2L-READ.14/1; R-A2L-001.1/3; R-A2L-READ.19/2; R-A2L-001.4/1; R-A2L-001.4/2; R-A2L-001.5/1; R-A2L-001.5/2; R-A2L-READ.64/1; R-A2L-READ.64/2; R-A2L-READ.65/5; R-A2L-READ.27/1; R-A2L-READ.32/2; R-A2L-READ.58/3; R-A2L-READ.58/5; R-A2L-READ.59/6; R-A2L-READ.60/2; R-A2L-READ.60/4; R-A2L-READ.60/6; R-A2L-READ.39/1; R-A2L-READ.61/1; R-A2L-READ.50/1**.
- Missing required consumer/UI routes or variants: **R-A2L-READ.56/3; R-A2L-READ.60/8; R-A2L-READ.60/9; R-A2L-READ.61/9; R-A2L-READ.65/6**.
- No assertion-based mutant oracle: **R-A2L-READ.65/4** (`tests/test_b103_a2l_reader_coverage.py:1568-1594` executes mutation/render loops but contains no assertion or executed-mutant count).
- Missing performance bound or isolating fixture: **R-A2L-READ.48/1** has no ≤120 s assertion (`tests/test_b103_a2l_reader.py:1634-1644`); **R-A2L-READ.49/2** still uses `RL_SWORD` instead of `RL.FNC.SWORD.ROW_DIR` (`tests/test_b103_a2l_reader.py:1776-1783`).
- The CRLF fixture defect persists in **R-A2L-READ.9/2**: the new node still applies `.replace("\n", nl)` after embedding CRLF and therefore creates CR-CR-LF (`tests/test_b103_a2l_reader_coverage.py:269-275`).

Examples of named tests whose docstrings overstate their assertions include READ.14/1 (`tests/test_b103_a2l_reader_coverage.py:423-438`, later BIT_MASK only), READ.27/1 (`:618-625`, non-None/key presence only), and READ.60/4 (`:904-922`, only one of three agreeing-duplicate shapes). These are coverage-implementation findings, not newly proven product defects.

### HIGH — READ.52 case_06 time is red; no READ.52 verified claim is supported

The static protocol now uses fresh processes, three-run medians, same-session base/current measurements when the base root is supplied, and pre-parse/peak-delta RSS reporting (`tests/test_b103_a2l_reader_perf.py:119-189`). Nevertheless, `test_r_a2l_read_52_case06_time` failed at `tests/test_b103_a2l_reader_perf.py:198`: **12.714064 s > 10.579511 s**, with base 7.053008 s (`evidence-e5/coverage-perf.txt:12-24`).

READ.52/2 and /3 arms passed in that transcript, but the family command exited 1. This re-audit therefore does not declare READ.52/1, /2, or /3 verified. A clean same-session perf run is required, at minimum with case_06 inside its unchanged bound.

### MEDIUM — matrix result cells and node references remain ahead of evidence

`02-test-cases.md` still records legacy `full/covered/verified` claims for the 37 partial IDs and READ.52, and most rows still point only to legacy nodes even where supplemental nodes now provide coverage. The repaired READ.4/5 and READ.48/2 rows are accurate (`02-test-cases.md:45`, `:288`), and the READ.51/1 pipe/row shape is repaired (`:301`), but the remaining cells require orchestrator review rather than blanket preservation.

### INFO — one original audit finding was a false premise

**R-A2L-READ.7/4** was already covered by the exact RP-B4 input `ECU_ADDRESS/*c*/0x1234` and address assertion in `tests/test_b103_a2l_reader.py:526-536`, especially `:530`. It is classified `false-premise`, not a new implementation gap.

## Corrected premises confirmed

- The hostile corpus contains **160** forms, not 162: 31+40+47+4+20+9+9 (`tests/test_b103_a2l_reader_coverage.py:1284-1286`). The differential asserts 160 and accounts for 157 ordinary REF comparisons + two UTF-16 refusal arms + the H3e current-behavior control (`:1534-1565`). This matches 159 comparisons plus one control and the CG-4 routing in `02-test-cases.md:17-25`, `:288`, `01-requirements.md:258`, and `codewire/graph-inc11.md:799`.
- READ.4/5 asserts header-address line 20 and LENGTH/MATRIX_DIM line 23 (`tests/test_b103_a2l_reader_coverage.py:228-240`). READ.14/2 uses its standalone line-1 fixture and asserts end/error line 5 (`:441-451`).
- The mixed-line-end builder avoids CR+LF fusion on empty lines (`:148-154`). This does not cure the separate READ.9/2 defect noted above.
- REF has quoted positional-token handling/unquoting (`tests/support/b103_a2l_ref.py:201-208`, `:622-704`), header-address source lines (`:1020-1030`), fail-closed invalid ECU_ADDRESS handling (`:1045-1070`), and disagreeing duplicate BIT_MASK refusal (`:1148-1161`). Its independence guard is at `tests/test_b103_a2l_reader_coverage.py:64-92`; `evidence-e5/coverage-hostile-green.txt:1-4` is green.
- P16 is at `tests/test_b103_a2l_reader_e5.py:431`; P17's actual product-route node is `tests/test_b103_a2l_reader_coverage.py:1796-1819`, not the E5 file. The combined 136-pass transcript includes both modules.

## Explicit blockers to marking result cells `verified`

1. **Every one of the 37 partial IDs listed above** remains blocked until its named residual input/assertion/route is implemented and exercised on Linux with a passing transcript. A green aggregate C+E run does not prove an unasserted observable.
2. **R-A2L-READ.52/1** is blocked by the current case_06 timing failure and `PYTEST_EXIT=1`. **READ.52/2 and /3** are also left unverified by this review because the only supplied family perf transcript is red; their passing individual arms do not justify declaring the READ.52 family verified.
3. **E5 as a whole** remains blocked by both the 37 static partials and READ.52's red perf run. `coverage-and-e5-green.txt` covers the supplemental C+E nodes only; it neither runs the perf family nor repairs static oracle gaps.
4. The 98 `full` rows and the one `false-premise` row have static support only. Any result-cell update is exclusively the orchestrator's action and must retain the actual transcript scope; this re-audit did not alter any cell.

## Evidence disposition

- Final supplemental evidence: `evidence-e5/coverage-and-e5-green.txt` — 136 passed, scratch package path printed first, exit 0.
- Hostile differential: `evidence-e5/coverage-hostile-green.txt` — 1 passed, exit 0.
- Performance: `evidence-e5/coverage-perf.txt` — 6 passed/1 failed/1 deselected, exit 1; authoritative blocker for READ.52.
- Earlier red coverage transcripts, including `coverage-tests-4.txt` (111 passed/1 failed over 112 C nodes), remain history and are not cited as green proof.
