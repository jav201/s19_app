# Inc 2 — A2L definition model: validation record (E5)

**Verdict: PASS-WITH-NOTES.** No MAJOR, HIGH or worse remains open. All functional, performance, mutant, review, trace and canonical law-guard gates are complete; the full suite and canon fold remain batch-end work.

This record closes Inc 2a and Inc 2b together. Inc 2a closed PASS-WITH-NOTES on 2026-11-07 with 216 covered cases; its evidence and open notes are preserved below. Inc 2b adds the scalar encode model, mask-preserving writes, ASCII and enum writes, limit and precision guards, the cross-kind overlap index and parse-error gate. Final product and tests are `e0f4553e`; `s19_app/tui/a2l_definition.py` has SHA-256 `60bf7cadcf26d9c2d7a74e1fd1d8553340525f8292c531ec3d37b5319d43a717`. The final tree has 321 active cases = 216 2a + 105 2b.

**Platform limit.** Functional, performance, mutant and law-guard runs are on <runner>, Python 3.11.18, Linux. Windows was used only for `py_compile`, static review and the trace checker. No UI or clipboard run belongs to this pure-model increment; operator key/dialog acceptance remains in Inc 8/9.

## Final runs

| Run | Result | Evidence |
|---|---|---|
| Final GREEN, model + synth | **322 passed** (310 model + 12 synth) | `../evidence/inc-2/int2b-run14-main.txt` |
| Real encode/`shared_with` stub | **125 failed, 197 passed**; every cited 2b/mixed RED appears | `../evidence/inc-2/int2b-red-stub-final9-main.txt` |
| Homonymous-mask guard removed | **1 failed, 309 deselected**; BLOB exemption reproduced | `../evidence/inc-2/int2b-red-homonym-guard.txt` |
| Performance, three serial runs | **22 passed each**, 52 bounds, 0 under 20% margin; `.136` 1.400–1.403 s / 2.000 s | `../evidence/inc-2/int2b-perf-57b-1.txt`, `../evidence/inc-2/int2b-perf-57b-2.txt`, `../evidence/inc-2/int2b-perf-57b-3.txt` |
| Mutants on final code | **34 killed / 0 survived / 0 not realisable** | `../evidence/inc-2/mutant-table-2b.md`, `evidence-e5/mutants-2b/out/` |
| Trace check | **1 US, 73 active requirements, 0 gaps** | `../evidence/inc-2/int2b-trace-check-final.txt` |
| Canonical law guards | **505 passed, 1 skipped**, 2 timing bounds with sufficient margin | `../evidence/inc-2/int2b-lawguards-final4-57b.txt` |

## Review verdicts

| Review | Final verdict | Record |
|---|---|---|
| Code | **PASS**, no HIGH/MAJOR; cross-page order and homonymous BLOB/INSTANCE exemption fixed and re-reviewed | `E5-code-review-2b-r4.md` |
| Security | **PASS-WITH-NOTES**, no HIGH/MAJOR | `E5-security-2b-r2.md` |
| Coverage | **PASS-WITH-NOTES**, 105/105 2b and 21/21 mixed rows without blocking overstatement; 125 cited RED = 125 actual | `E5-coverage-audit-2b-r3.md` |

The failed intermediate reviews are retained. R3 found that a BLOB or INSTANCE could inherit a homonymous tag's mask; the final `_pair_exempt` returns fail-closed before `mask_of`, and `.138/23` covers both shapes. Coverage findings led to non-vacuous RED assertions, the complete six-conversion/mask/decimal/17-digit `.55` grid, scalar-only AT-I2-2 wording, `.152` decode checks and missing overlap assertions.

## Inc 2a evidence retained

Inc 2a previously closed with 199 passed, 1 deselected; 22 performance tests in each of three runs; 63 killed mutants and one then-unrealisable `.58.1` encode arm (now killed in the 2b battery); security census and seeded-mutation runs; and a 216-case coverage audit. Its earlier verdict was PASS-WITH-NOTES, with no MAJOR/HIGH open. See `../evidence/inc-2/fix-tests-green-main.txt`, `../evidence/inc-2/mutant-table-A.md`, `../evidence/inc-2/mutant-table-B.md`, `../evidence/inc-2/sec-e5r2-census-transcript.txt` and `../evidence/inc-2/E5-coverage-audit.md`.

## Open notes

- **LOW:** bidi and other Unicode format characters are preserved by the model contract; Inc 8/9 must isolate or filter them in the renderer. This carries forward BL-I2-18.
- **INFO:** the encode path checks image bytes twice for masked writes; this is redundant, not a correctness failure.
- **Coverage evidence granularity:** RED is per test node, not per arm. `.138/23` stops on BLOB in its specific RED; INSTANCE is exercised in GREEN and by the common guard. Seventeen mixed rows cite only their encode node although their older describe/decode nodes also participate in the suite.
- **Future oracle robustness:** `_SCALAR_DEFC` is a manual list; a future scalar added to the generator should also be added there or checked by a census assertion.
- **CR-8 / E5S-08 / E5S-09:** the Inc 2a notes about the closed describe section list, Inc 3a record wording and timing ratios under load remain records, not new 2b regressions.
- **Full suite and canon fold:** owed at batch end, not claimed here. No Windows runtime result and no snapshot result is claimed.

## Models and execution

Implementation and early reviews used DeepSeek and Kimi. After DeepSeek's token exhaustion, the operator-directed Kimi agents completed the final code, security and coverage reviews. The orchestrator ran all functional, performance, law and mutant executions. No failed test was called flaky.

## Evidence index

The canonical copies under `../evidence/inc-2/` are the final GREEN, RED, homonym, three performance and trace transcripts, plus `mutant-table-2b.md`. Their SHA-256 values, re-derived at those paths, are in `evidence-e5/int2b-evidence-sha256.txt`; `.gitattributes` stores all evidence as `-text`. The per-mutant diffs and outputs remain in `evidence-e5/mutants-2b/out/`; intermediate failures and harness corrections remain in `evidence-e4/` and `evidence-e5/` for audit history.
