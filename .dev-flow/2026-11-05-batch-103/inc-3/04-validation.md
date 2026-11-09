# Inc 3a — A2L definition model II: validation record (E5)

**Verdict: PASS-WITH-NOTES.** No MAJOR, HIGH or worse is open. Inc 3a has **71 active requirements / 280 cases**: **275 full + 5 partial, 0 gap**. Every full case is covered and verified; the five mixed cases have their read arm verified and their edit arm explicitly deferred to Inc 3b. The 42 Inc 3b cases remain `gap` / `not_run`. Written 2026-11-09.

**Platforms.** Final functional, timing, cap, scalar-performance and mutant-B runs used `<runner>`, Python 3.11.18. Mutant A and law guards used the operator-provided laptop `<runner>`, Python 3.11.18. Windows execution was limited to `py_compile`; no Windows test result is claimed.

## Final runs

| Run | Result | Evidence |
|---|---|---|
| Functional integration | **471 passed, 35 deselected** | `../evidence/inc-3/evidence-e5-green-final.txt` |
| Final RED on the Inc 3a base | **269 failed, 6 passed, 34 deselected**; no collection/fixture errors | `../evidence/inc-3/evidence-e5-red-final.txt` |
| Full array timing | **33 passed, 1 deselected**; 96 bounds, 0 under 20 % margin | `../evidence/inc-3/evidence-e5-timing-final.txt` |
| FIX cap `.142/5` | 1 passed; **0.090 / 1.000 s**, peak **1.2 MiB** | `../evidence/inc-3/evidence-e5-fix-cap5-green.txt` |
| FIX cap `.142/6` | 1 passed; **0.514 / 5.000 s**, peak **63.5 MiB** after the PAR_LIST correction | `../evidence/inc-3/evidence-e5-fix-cap6-green-fixed.txt` |
| `.147/9` hostile shift | 1 passed, refusal within 1.0 s | `../evidence/inc-3/evidence-e5-fix147-9.txt` |
| Scalar Inc 2a performance | **22 passed**; 52 bounds, 0 under 20 % margin | `../evidence/inc-3/evidence-e5-scalar-perf.txt` |
| Synth, including slow pin and determinism | **3 passed**; final full synth file **9 passed** | `../evidence/inc-3/evidence-e5-synth-cited.txt`, `../evidence/inc-3/evidence-e5-synth-final.txt` |
| Law guards | **375 passed, 1 skipped**; skipped TC-027 then **1 passed** explicitly; final ID/engine selection **13 passed** | `../evidence/inc-3/evidence-e5-lawguards-laptop-final.txt`, `../evidence/inc-3/evidence-e5-tc027-laptop.txt`, `../evidence/inc-3/evidence-e5-id-registry-final.txt` |
| Mutant A | **61 KILLED, 0 SURVIVED, 0 BAD** across the full run plus the corrected M-141 arm | `../evidence/inc-3/evidence-e5-mutants-A-final.txt`, `../evidence/inc-3/evidence-e5-mutants-A-M141.txt` |
| Mutant B | **29 KILLED, 0 SURVIVED, 0 CRASH, 0 BAD** | `../evidence/inc-3/evidence-e5-mutants-B-run.txt` |
| Supplemental mutants | **13 KILLED** across the extra run and corrected M-148-reduce arm | `../evidence/inc-3/evidence-e5-mutants-extra-run.txt`, `../evidence/inc-3/evidence-e5-mutant-M148-reduce.txt` |

Total practical mutants: **103 KILLED, 0 open survivors**. Timing-only and non-discriminating controls are listed separately in the mutant README/build reports, not counted as kills.

## Review verdicts

- **Code:** `../evidence/inc-3/evidence-e5-code-review-1.txt` — **PASS-WITH-NOTES**. Empty-kind element count and array span defects are closed.
- **Security:** `../evidence/inc-3/evidence-e5-security-review-1.txt` — **PASS-WITH-NOTES**, no confirmed crash, collision, immutability or fail-open defect.
- **Final targeted re-review:** `../evidence/inc-3/evidence-e5-final-review-2.txt` — **PASS-WITH-NOTES**. PAR_LIST keeps values and refusals unchanged and avoids aliases to parser payload.
- **Coverage:** `../evidence/inc-3/evidence-e5-coverage-audit-1.txt`, `../evidence/inc-3/evidence-e5-coverage-audit-2.txt`, `../evidence/inc-3/evidence-e5-coverage-audit-3.txt` — initial gaps and partials corrected; final remaining points all full, no unrun arm.

## Open LOW notes / backlog

- Multiple FIX forms on one AXIS_DESCR use deterministic PAR > PAR_DIST > PAR_LIST precedence; no corpus object declares more than one and the requirement has no explicit multi-form case.
- A hostile MATRIX_DIM line with very many words can exceed the aggregate 1,024-character message bound, although each word is echo-capped. No memory-safety impact; recorded as a LOW design-gap.
- A truncated FIX form can fall through to the no-points refusal rather than the cannot-read wording. No crash; no pinned case.
- Timing-only read/echo/lookup mutants and non-discriminating cited controls are documented in `../evidence/inc-3/evidence-e5-mutants-extra-builder.txt`; no assertion was weakened to eliminate a survivor.

## Not run here

- The complete repository suite: reserved for batch end.
- Inc 3b encode cases and the five mixed edit arms: require Inc 2b/3b, not Inc 3a.
- Real Windows Terminal UI captures: no UI changed here; Inc 12 owns its captures and operator approval.

## Trace check

Final command on committed Linux clone `1452c838afe6`: `trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-3/01-requirements.md --base e07fb00 --src s19_app/tui/a2l_definition.py tools/synth/make_release_case.py`.

**Result: 1 US, 85 active requirements, 12 gaps.** All 12 are TEST gaps on the Inc 3b rows R-A2L-DEF.122 … .132 and .140. **0 EVID gaps and 0 gaps on any Inc 3a row.** Transcript: `../evidence/inc-3/evidence-e5-trace-check-final.txt`. The earlier path-convention failure is retained as history in `../evidence/inc-3/evidence-e5-trace-check.txt`.

## Models

Kimi conducted integration, corrections, records and rulings. DeepSeek v4 Pro implemented mechanical product/test/coverage passes, reviews, timing and mutant drivers. Independent functional RED/GREEN, code, security and coverage reviews were used. No source mutation was made in the real worktree and no threshold or assertion was weakened to obtain a pass.
