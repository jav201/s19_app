# Inc 12 — A2L tag table: validation record (E5)

**Verdict: PENDING.** Product, independent tests, law guards, static reviews and the 20-arm mutant battery are complete. Canonical snapshot regeneration and the operator's visual verdict are still open. No merge to `batch-103`, `main`, or push is authorized by this record.

## Final runs

| Run | Result | Evidence |
|---|---|---|
| RED on the Inc 12 base | **110 failed, 2 passed**, no collection/fixture errors | `../evidence/inc-12/evidence-e4-red-final.txt` |
| Final 112-node suite | **112 passed in 811.67 s** on commit `1a907685` | `../evidence/inc-12/evidence-e4-green-final7.txt` |
| Resize determinism | **10/10 passed** after restoring the E2 rebuild | `../evidence/inc-12/evidence-e4-resize-rebuild-x10.txt`, `E4-resize-ruling.md` |
| Existing consumers | **64 passed, 1 failed**; only the pre-existing case-06 timing bound | `../evidence/inc-12/evidence-e4-consumers-final3.txt` |
| Isolated case-06 timing | **1 failed in 29.06 s**; 220,040 tags refreshed in **1.372 s** against the 1.000 s bound | `../evidence/inc-12/evidence-e4-case06-timing-final.txt` |
| Complete law guards | **221 passed in 361.56 s** | `../evidence/inc-12/evidence-e5-lawguards-final2.txt` |
| Mutation runner self-test | **PASSED** | `../evidence/inc-12/evidence-e5-mutant-selftest.txt` |
| Mutation battery | **20/20 KILLED**, no survivor, CRASH or BAD | `../evidence/inc-12/evidence-e5-mutants-final4.txt`, `../evidence/inc-12/evidence-e5-mutant-M2-retry.txt` |
| Real Windows Terminal | 28 before/after PNGs at 80, 118 and 220 columns plus mid-scroll and Name-line; all sidecars ready | `../evidence/inc-12/captures/final/` |
| Decision page | 28 images, 0 broken, 0 console errors, 0 failed requests | `../evidence/inc-12/evidence-e5-decision-browser.txt`, `evidence-e5/DECISION.html` |

The case-06 timing failure is also present on the base (1.399 s) and integrated tree (1.428 s) against 1.000 s. An isolated rerun on `1a907685` measured 1.372 s. It is not attributed to Inc 12 and remains open for the batch-end performance review; no flaky classification is claimed.

## Reviews

- Code and security: **PASS-WITH-NOTES** (`E4-code-review.md`). No MAJOR/HIGH/MEDIUM finding remains open.
- Coverage: static **PASS** for 33 full cases plus AT-B103-I12-1 (`E4-coverage-audit.md`). AT-B103-I12-2 remains `gap` / `not_run`.
- Mutation runner: initial instrument findings corrected and self-test passed (`E5-mutant-runner-review.md`). M2 initially survived the off-screen oracle; after `require_visible`, 41 nodes passed and the isolated retry killed it (`../evidence/inc-12/evidence-e5-visible-fixed-cells.txt`).

## Open items

- Six A2L snapshot baselines must be regenerated in the canonical CI environment. The two Patch snapshot mismatches already fail on base and are not included in that update (`../evidence/inc-12/evidence-e5-snapshot-base.txt`, `../evidence/inc-12/evidence-e5-snapshot-final.txt`).
- AT-B103-I12-2 awaits the operator's verdict on `evidence-e5/DECISION.html`, including look-alike names at 80 columns, the left-cut backlog cell and the Name-line row cost.

## Not run here

- The complete repository suite and requirements-canon fold remain reserved for batch end.
- No mutation was run in the real worktree. No local snapshot baseline was regenerated.

## Trace check

Final `trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-12/01-requirements.md --base e07fb00 --src s19_app/tui/app.py`: **1 US, 8 active requirements, 0 gaps** (`../evidence/inc-12/evidence-e5-trace-final.txt`). The earlier structural check reported only the missing validation file and the US column issue (`../evidence/inc-12/evidence-e5-trace.txt`).

## Models

Kimi conducted integration, corrections, records and rulings. DeepSeek implemented mechanical product/test/capture/mutation drivers. Independent test, code, security, coverage and instrument reviews were used. No source mutation was made in the real worktree and no threshold or assertion was weakened to obtain a pass.
