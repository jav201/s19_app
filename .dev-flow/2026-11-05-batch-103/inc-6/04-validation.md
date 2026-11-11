# Inc 6 — Picker correctness: validation record (E5)

**Verdict: PENDING historical regression family.** Product is GREEN on 21 requirements and 77 cases. Final coverage is 75 full + 2 partial; 75 covered + 2 partial. Code/security review: PASS. Coverage audit: PASS-WITH-NOTES only for `.021`’s mounted route.

**Platform.** Linux runner, Python 3.11.18, isolated HOME/XDG/LOCALAPPDATA, closed stdin, bytecode disabled. Accepted transcripts print the tested clone’s `s19_app.__file__`. Windows was used for static checks only.

## Confirmed runs

| Run | Result | Evidence |
|---|---|---|
| Base RED — model | 33 failed / 11 passed | `evidence-e4/base-red-model.txt` |
| Base RED — editor | 29 failed / 2 passed | `evidence-e4/base-red-editor.txt` |
| Focused corrections | 6 passed | `evidence-e4/focused-green.txt` |
| Addendum `.020/.021` | 4 passed | `evidence-e4/addendum-green.txt` |
| Final functional family | **77 passed in 396.51 s** | `../evidence/inc-6/final-functional-green.txt` |
| Mutant baseline | 77 passed | `../evidence/inc-6/mutant-baseline-green.txt` |
| Mutation controls | **21 killed / 0 survived / 0 errors / 0 timeouts / 0 BAD** | `../evidence/inc-6/mutants-initial.txt`, `../evidence/inc-6/mutants-corrected.txt`, `../evidence/inc-6/mutant-summary-final.json` |
| Project law guards | **550 passed, 3 skipped, 1 inherited redaction failure** | `../evidence/inc-6/law-guards.txt` |
| Historical regression family | **PENDING** | `../evidence/inc-6/historical-green.txt` (not yet written) |

The inherited redaction failure is confined to Inc 12 and `inc-2/steps.log`; the official Inc 6 scan has **0 hits**. Those inherited records are unchanged. `test_id_registry`’s bound was deliberately advanced 297→299 for the two new test modules. `.019/1` is the only serial timing arm; `.019/2` is the deterministic rebuild census.

## Reviews and limitations

- **Code:** `E5-code-review.md` — PASS. E3 design-gap `.021` added the missing Check preflight; no HIGH/MAJOR remains.
- **Security:** `E5-security-review.md` — PASS. No unsafe length fallback, giant/partial read, injection or new write path.
- **Coverage:** `E5-coverage-audit.md` — PASS-WITH-NOTES. All requirements and cases map to real nodes. `.021/1-2` are `partial`: synchronous handler evidence is strong, but mounted `run_test` attempts stalled and are not claimed.
- **Layer 0:** `set_parameters`, `_format_parameter` and Check’s missing-length guard meet decision/boundary criteria and are covered by requirements/mutants. No unit lacks an owning requirement.

**Correction population:** record/test/count changes were reconciled in requirements, ledger, slice, graph, steps and this record. Conditional-gate discharge: E3 initial findings, E3 addendum and E5 code/security findings were all re-reviewed and closed.

**Instrument RED-proof:** base RED transcripts, mutant baseline and 21 killed controls demonstrate the instruments can fail. Code-Wire lint reads 20 nodes/3 entities/22 findings with 0 unread lines.

**Not run here:** the complete repository suite. By operator amendment it runs after Inc 6 but does not block integration or push to main; its findings go to the next batch and must not be reported as full-suite PASS. Trace final and merge-clone verification are also pending.
