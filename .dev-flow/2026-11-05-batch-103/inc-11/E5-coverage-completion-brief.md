# Inc 11 E5: complete the independent coverage audit (DeepSeek)

Start only after the product-finding corrections are green. You are an independent tester, not the author of the original cases. Do not edit product code and do not commit.

Read `inc-11/E5-coverage-audit.md` in full and `inc-11/E5-rulings.md`'s coverage section. The audit found 27 missing and 109 partial requirement cases incorrectly marked full, plus READ.52's protocol gaps. The two real-app ATs are already full and need no new coverage.

## Scope

- Add focused supplemental tests in a new file `tests/test_b103_a2l_reader_coverage.py`, reusing helpers instead of duplicating large fixtures.
- Modify `tests/test_b103_a2l_reader_perf.py` only to implement the required READ.52 protocol.
- Modify a legacy test only when the audit's required consumer route belongs there (for example encode/describe or picker behavior). Name every such file in your report and keep the change targeted.
- Do not edit `tests/test_b103_a2l_reader.py`, `tests/test_b103_a2l_reader_e5.py`, product code or `02-test-cases.md`; the orchestrator owns the result cells.

For every one of the 27 missing and 109 partial case ids, either add the named input/assertion through the real product route or demonstrate precisely why the audit item was already covered. Do not downgrade a case merely to close the gate. A broad differential or fixture may discharge a case only when it asserts that case's exact observable. Keep the two real-app ATs unchanged.

READ.52 must compare base and current in the same session, in fresh processes, using the median of 3 runs, report pre-parse RSS and peak-minus-before, and preserve the existing time/memory bounds and exact diagnostics. Do not weaken the thresholds.

## Evidence

On this PC run only `python -m py_compile` on the changed test files. All pytest runs happen on the Linux runner with the absolute s19ci Python, `PYTHONDONTWRITEBYTECODE=1`, closed stdin and HOME/XDG/LOCALAPPDATA under `/tmp/b103-e5-11-coverage/<user>` (never a final component named `home`). Print `s19_app.__file__` first.

Run the new/changed tests, the whole reader, the modified legacy tests and the perf arms. Save complete transcripts and exit codes under `inc-11/evidence-e5/coverage-*.txt`. Produce `inc-11/evidence-e5/coverage-completion-report.md` listing each of the 136 case ids, the test node that discharges it, and any residual gap or false audit premise. Do not type a green result without its transcript.

Do not run mutants, edit product, push, merge, write the OS clipboard or touch `~/work/b103-int11`. Report any product failure instead of fixing it; the orchestrator will rule it.
