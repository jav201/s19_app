# Inc 5 — A2L refresh: validation record (E5)

**Verdict: PASS-WITH-NOTES; Inc 5 closed and integrated.** Product commit `5e8f0454`; final test SHA-256 `d061bafb42d27999e5faec26c46819ba9b612ef6f01e4ef2e9d604e6ac08c8f7`. **28 requirements / 103 cases: all full, covered and verified.** No HIGH/MAJOR review finding is open. The note is the inherited repository redaction-law failure outside Inc 5.

**Platform.** Linux `<runner>`, Python 3.11.18, isolated HOME/XDG/LOCALAPPDATA, stdin closed and bytecode disabled. Every accepted functional/mutant/law transcript prints the imported `s19_app.__file__` from the tested clone. Windows was limited to syntax/static checks and the official redaction scan.

## Final runs

| Run | Result | Evidence |
|---|---|---|
| Base RED | **88 failed / 15 passed**; corrected `.011` rerun **3 failed / 2 passed** | `evidence-e4/base-red-full.txt`, `evidence-e4/base-red-r011.txt` |
| Functional family | **112 passed in 1713.14 s** — 103 Inc 5 + 9 related historical cases | `../evidence/inc-5/final-functional-green.txt` |
| Mutant baseline | **103 passed in 1690.58 s** | `../evidence/inc-5/mutant-baseline-green.txt` |
| Mutants | **28 killed / 0 survived / 0 ERROR / 0 TIMEOUT** | `../evidence/inc-5/mutants-final.txt`, `../evidence/inc-5/mutant-m024-killed.txt`, `../evidence/inc-5/mutant-summary-final.json` |
| Canon/ID/docs laws | **254 passed, 1 skipped** | `../evidence/inc-5/law-canon-id-docs.txt` |
| Direction-B laws | **184 passed** | `../evidence/inc-5/law-directionb.txt` |
| Suite hygiene | **64 passed, 2 skipped, 1 inherited redaction failure** | `../evidence/inc-5/law-suite-hygiene.txt` |
| Official Inc 5 redaction scan | **inc5_redaction_hits=0**, both evidence roots | `../evidence/inc-5/redaction-report.txt`, `../evidence/inc-5/redaction-scan.txt` |
| Trace | **1 US, 28 active requirements, 0 gaps**, including committed EVID and SLICE | `../evidence/inc-5/trace-final.txt` |

The initial mutant table killed 27. M-024 survived because it removed only the redundant method-level guard after the real `^L` action had already refused busy. The corrected M-024 disables the actual `action_load_file` guard and produces four behavioral failures (`../evidence/inc-5/mutant-m024-killed.txt`). The summary reconciles 28 kills on the unchanged product/test tree; baseline and the other 27 controls were not needlessly repeated.

The preceding complete functional attempt produced **108 passed / 4 failed** (`evidence-e4/final-functional-r024-fixture.txt`). All four failures were one fixture error: `.024` waited for a dialog although the product refuses `^L` before opening it during busy. The corrected arm is **4 passed** (`evidence-e4/r024-busy-route-green.txt`); the accepted 112-case result comes from a fresh complete run, not combined partials.

The suite-hygiene failure names only inherited Inc 12 evidence and `inc-2/steps.log`; it is not called GREEN and those records are unchanged by Inc 5. Inc 5's own records pass the official scan.

## Reviews

- **Code:** `E5-code-review.md` — **PASS**.
- **Security:** `E5-security-review.md` — **PASS**.
- **Coverage:** `E5-coverage-audit.md` — **PASS-WITH-NOTES**. Generic Split read-back and deliberate `.028` mismatch injection are documented; neither leaves a requirement uncovered.
- **Mutation driver:** DeepSeek's count finding was ruled a false positive using substring semantics and executable evidence (`E5-mutant-driver-ruling.md`). M-024 was corrected as described above.

## Not run here

The complete repository suite will be launched after Inc 6. By explicit operator amendment on 2026-11-10 it will not block integration or push to `main`; its findings go to the next batch and must not be reported as a full-suite PASS. Requirements-canon fold and global trace remain separate.

Integration into `batch-103` is merge `23defa7f98106e80b72f0bdd58ea2547a6527de3`. A detached Linux clone of that exact hash reports **112 passed in 1715.02 s** (`../evidence/inc-5/merge-functional.txt`) and **1 US, 28 active requirements, 0 gaps** (`../evidence/inc-5/merge-trace-initial.txt`). The session handoff is `../HANDOFF-2026-11-10-KIMI-INC5-TO-INC6.md`; no Inc 6 work has started.
