# Inc 11 E4: complete the READ.48 reference-oracle corrections (DeepSeek)

This continues `E4-oracle-fix-brief.md` in the same worktree and with the same uncommitted CURVE/VALUE correction. Preserve that correction. You are the independent tester. Do not commit.

## Current evidence

The CURVE/VALUE synthetic case is green, but `test_r_a2l_read_48_tracked_files_equal_ref` now reaches previously hidden differences. The whole reader file gives `1 failed, 178 passed`. The first agent's report is `inc-11/evidence-e4/int-oracle-agent-report.txt`.

Three reference-reader defects remain:

1. `_read_spans` resolves typedefs in one pass, so an INSTANCE whose TYPEDEF is declared later loses its length. The product correctly collects typedefs before reading spans. Make the reference two-pass without changing span order.
2. The reference `/include` diagnostic lacks the exact `Line <n>: ` prefix required by R-A2L-READ.22.
3. The reference emits spurious arity/duplicate errors for valid body keywords `UNIT unit` in `examples/case_07_stress_smoke/firmware.a2l`; the product correctly emits none. Diagnose the actual parser path rather than special-casing UNIT or this file.

## Authority and scope

Read the relevant definitions and rows in `inc-11/01-requirements.md`: keyword arities (including UNIT), R-A2L-READ.22, READ.29, READ.41 through READ.45 and READ.48. Compare the product read-only where useful.

You may edit only:

- `tests/support/b103_a2l_ref.py`
- `tests/test_b103_a2l_reader.py`

Add focused synthetic differential coverage for each corrected class where it is not already pinned: a forward typedef, the exact `/include` error with its line, and a valid UNIT body keyword. Keep changes targeted and match existing style. Do not edit product, requirements, graphs, records, or other files.

## Execution

On this PC run only `python -m py_compile` on the changed test files. Use the existing fresh clone at `/tmp/b103-e4-11-oracle-kimi/tree`; copy only your changed test files there. Use the absolute s19ci Python, `PYTHONDONTWRITEBYTECODE=1`, closed stdin, and the existing isolated `zq_iso_user` environment.

Run the focused cases, then `test_r_a2l_read_48_tracked_files_equal_ref`, then the whole `tests/test_b103_a2l_reader.py` with `-m "not serial_timing"`. Save the complete final reader transcript as `/tmp/b103-e4-11-oracle-kimi/followup-reader.log`, including the exit code, and copy it to `inc-11/evidence-e4/int-oracle-followup-reader.txt` in the local worktree. If other differences surface, report them; do not broaden into product changes.

Do not run timing tests, push, merge, reset, delete branches, write the OS clipboard, or touch `~/work/b103-int11`. Do not use proprietary A2L material.

## Report

Give the exact diff summary, test counts and exit codes, explain each root cause, and name any remaining failure. Do not claim E4 green from these reader tests alone.
