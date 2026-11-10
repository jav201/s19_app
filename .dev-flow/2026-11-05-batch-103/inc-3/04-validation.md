# Inc 3b — A2L definition writes: validation record (E5)

**Verdict: PASS-WITH-NOTES.** No HIGH/MAJOR is open. **86 requirements / 344 cases = 280 3a + 64 3b; all 344 full, covered and verified.** Product tree `98904e82`; functional/scale/performance evidence `43276135`; sanitized records `cd5757b6`. The open note is an inherited redaction-law failure outside Inc 3, proved on base; it is not called GREEN.

**Platform.** Linux `<runner>`, Python 3.11.18, real Git checkout, isolated neutral HOME/XDG/LOCALAPPDATA, stdin closed and bytecode disabled. Windows was limited to `py_compile` and static reviews.

## Final runs

| Run | Result | Evidence |
|---|---|---|
| Integrated write + synth | **81 passed** | `evidence-e4/write3b-run9-int.txt` |
| Functional family | **668 passed**; 4 timing bounds, 0 under 20 % | `evidence-e4/write3b-family-final-98904e82.txt` |
| Base RED | **58 failed / 5 passed**, behavioral, on `c089df37` | `evidence-e4/write3b-red-base.txt` |
| Array scale | **34 passed**, 96 bounds, 0 under 20 %, 530.41 s | `evidence-e4/write3b-arrays-scale-final.txt` |
| Scalar performance ×3 | **22 passed each**, 52 bounds each, 0 under 20 %; 251.03 / 246.32 / 245.85 s | `evidence-e4/write3b-definition-perf-run{1,2,3}.txt` |
| Mutants | **28 killed / 0 survived**, 17 write rows + 6 E5 controls + 5 mixed arms | `evidence-e5/mutant-table-3b.md`, `evidence-e5/mutants-3b/` |
| Trace | **1 US, 88 active requirements, 0 gaps** | `evidence-e5/write3b-trace-final.txt` |
| Canon/ID/docs laws | **254 passed, 1 skipped** | `evidence-e4/write3b-law-canon-id-docs-final.txt` |
| Suite hygiene | **64 passed, 2 skipped, 1 failed** — only redaction | `evidence-e4/write3b-law-suite-hygiene-final.txt` |
| Direction-B laws | **184 passed** | `evidence-e4/write3b-law-directionb-final.txt` |
| **Law total** | **502 passed, 3 skipped, 1 inherited redaction failure** | the three chunks above |

The two earlier combined law attempts were not accepted: the archive lacked `.git`; the 600-second combined run had no summary. The corrected real-checkout chunks above supersede them.

Inc 3's evidence was sanitized reproducibly and the official scan reports **inc3_redaction_hits=0** (`evidence-e5/write3b-redaction-scan-2.txt`). The full redaction law still fails only on inherited Inc 12 evidence and `inc-2/steps.log` (`evidence-e4/write3b-law-redaction-after-inc3.txt`). The base reproduction is `8cb8f479`, in `evidence-e4/write3b-redaction-base-head.txt`; those files were left intact as instructed.

## Reviews

- **Code:** `E5-code-review-3b-rereview.md` — **PASS**. Span candidates, tolerance/file order, RMQ, NaN and message bounds closed.
- **Security:** `E5-security-3b-rereview.md` — **PASS**, 0 MAJOR remaining.
- **Coverage:** `E5-coverage-audit-3b.md` — **PASS**, 344 cases and 64 write tests one-to-one.
- **Mutation-driver audit:** three non-discriminating controls were fixed before execution; all 28 final mutants were killed.
- **Packet audit:** suite status, inherited cause and base citation corrected before closure.

## Contract amendments

Nonfinite TAB_INTP fractions and any NaN-y TAB_INTP are not invertible and refuse without bytes. The frozen oracle raises on the first and has no sound ordered domain on the second; `.131/4` records the amendments. TAB_NOINTP keeps first-file-order tolerance matching through the precomputed range-minimum tree.

## Not run here

The complete repository suite and canon fold belong to batch end. No UI changed, so no new UI capture is owed. Integration into `batch-103` is next, followed by merge-clone functional and trace checks.
