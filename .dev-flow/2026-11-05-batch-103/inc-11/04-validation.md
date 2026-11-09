# Inc 11 — A2L reader: validation record (E5)

**Verdict: PASS-WITH-NOTES.** No MAJOR, HIGH or worse is open. The increment has **81 active requirements** (two tag-table rows withdrawn here and moved to Inc 12), **271 cases + 2 acceptance cases**, all `covered` and `verified`. Code-Wire has **39/40 nodes**. Written 2026-11-09.

**Platforms.** Final integration, READ.52 and mutant B ran on `cachyos-rtx`, Python 3.11.18. Mutant A ran on the operator-provided CachyOS laptop `lnx1`, Python 3.11.18. Earlier laptop-only results are retained as history, not as the final RTX verdict. Windows mutant output is noncanonical supporting material only and is excluded from this verdict.

## Final runs

| Run | Result | Evidence |
|---|---|---|
| P18 and supplemental coverage | 148 passed, including the 160,000-mutant hostile node | `evidence-e5/p18-red.txt`, `evidence-e5/p18-green.txt`, `evidence-e5/p18-e5-coverage-green-2.txt` |
| Final integration run 13 | **A 332 passed; B 200 passed; C 389 passed + 1 skipped; D 215 passed + 4 skipped** | `../evidence/inc-11/int-green13.txt` |
| READ.52 on the reference host | **7 passed, 1 deselected**; case_06 **8.411 / 8.843 s (4.9 % margin)**, software_a 11.6 %, all memory arms green | `../evidence/inc-11/coverage-perf-rtx-final.txt` |
| READ.65/6, deselected by the serial marker | 1 passed; both 4.8-million-word forms parse and render | `../evidence/inc-11/read65-6-green.txt` |
| Direct `_infer_length_characteristic` callers | 9 passed | `../evidence/inc-11/record-layout-length-green.txt` |
| Mutant A on `14fdc3b9` | **19 KILLED, 1 NOT_REALISABLE (M10), 0 SURVIVED, 0 CRASH**; restored baseline 332 passed | `../evidence/inc-11/mutant-table-linux-A.md`, `../evidence/inc-11/final-baseline-green.txt` |
| Mutant B on `14fdc3b9` | **23 KILLED, 0 SURVIVED, 0 CRASH, 0 BAD**; restored baseline 522 passed + 1 deselected | `../evidence/inc-11/mutant-table-linux-B.md`, `../evidence/inc-11/mutants-linux-B-final-green.txt` |
| P17 near-name exactness | Both scalar equality arms changed to `startswith`; RED `enum != number`, then restored GREEN | `../evidence/inc-11/mutants-linux-B-P17-exactness.txt` |

M10 is `NOT_REALISABLE` on the public route, not a survivor requiring a product change: the in-memory mutation changes private lexer line numbers while universal-newline input leaves the public reading identical (`../evidence/inc-11/mutants-linux-A-M10-public-proof.txt`).

## Review verdicts

- **Code:** `E5-code-final-review-3.md` — **PASS**. The preceding FAIL was traced to a stale REF scratch and is not a defect of `14fdc3b9`.
- **Security:** `E5-security-final-review-2.md` — **PASS-WITH-NOTES**, no HIGH/MEDIUM. The LOW note is a quoted-positional-datatype permissiveness/oracle divergence with no memory-safety impact.
- **Coverage:** `E5-coverage-reaudit-2.md` plus the runtime reconciliation — **37 full, 0 partial, 0 gap**, all 37 dynamically verified. READ.70/1–3 and READ.51/1 were reconciled to their real nodes; no requirement row remains `gap`, `partial` or `not_run` outside moved history.
- **P18 independent review:** `E5-p18-independent-review.md` — **PASS**.

## Open LOW notes / backlog

- REF-only latent limitations outside the declared corpus: deposit/layout precedence, count-unit diagnostic text and no external-axis post-pass. They are not product findings or current differential failures.
- Quoted positional MEASUREMENT datatype is accepted by the product but not REF; P1 covers numeric words and the result remains bounded by the declared datatype table. No behavior change is made at E5.
- M10's private raw-CR lexer path is not pinned because the public reader normalizes it away. A future `newline=""` or raw-element caller must add a direct test.
- `coverage-perf-rtx-final.txt` leaves 4.9 % case_06 margin, not the earlier 0.2 % laptop margin. No threshold was changed.

## Not run here

- The complete repository suite: reserved for batch end, after all increments.
- Windows execution: not part of the final verdict. Inc 12 owns the real Windows Terminal captures and approval.
- H3e: explicitly routed to Inc 3a by CG-4; the Inc 11 differential compares 159/159 shapes plus its current-behavior control.

## Trace check

Final command: `trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-11/01-requirements.md --base e07fb00 --src s19_app/tui/a2l.py s19_app/tui/a2l_extract.py s19_app/tui/a2l_definition.py`, on a committed Linux clone. Preliminary result before this record: only `no 04-validation.md` (`evidence-e5/trace-check-prelim-2.txt`). Final transcript: `../evidence/inc-11/trace-check-transcript.txt`.

## Models

Kimi conducted integration, corrections and rulings. DeepSeek v4 Pro performed mechanical coverage, matrix reconciliation, reviews and mutant drivers. Final code and security reviews were independent read-only passes. No product or test edit was made to kill a survivor or weaken a bound.
