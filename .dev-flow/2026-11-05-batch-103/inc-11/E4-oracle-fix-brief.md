# Inc 11 E4: correct the CURVE INSTANCE reference-reading fault (DeepSeek)

Worktree: `C:\Users\jjgh8\Github\s19_app-b103-inc11-code`, branch `b103-inc11-code`, base HEAD `1075fe48`.

## Finding

A full Git clone of HEAD `1075fe48` on the Linux runner gave `1 failed, 983 passed, 2 skipped` for the Inc 11 integration battery. The only failure was `tests/test_b103_a2l_reader.py::test_r_a2l_read_48_tracked_files_equal_ref`.

For `ASAM_I_MAP_COM_AXIS_FIX_AXIS`, the product reader returns `length=None` and the reference reader returns `length=2`.

## Authority

Read only the relevant rows and code:

- `.dev-flow/2026-11-05-batch-103/inc-11/01-requirements.md`, R-A2L-READ.43 and R-A2L-READ.45 (around lines 248-250).
- `tests/support/b103_a2l_ref.py`, `_read_span` (around lines 1417-1475).
- `s19_app/tui/a2l.py`, `extract_declared_spans` (around lines 3804-3893), as a read-only comparison.
- The tracked public fixture `examples/case_00_public/ASAP2_Demo_V171.a2l`, around line 5482.

R-A2L-READ.43 covers only VALUE, VAL_BLK and ASCII typedefs. R-A2L-READ.45 requires no length when an INSTANCE cannot be sized by READ.42 through READ.44, including a CURVE TYPEDEF_CHARACTERISTIC. The product is correct; the reference reader is wrong.

## Scope

You are the independent tester. You may edit only:

- `tests/support/b103_a2l_ref.py`
- `tests/test_b103_a2l_reader.py`, only if a focused synthetic differential case is needed to pin the CURVE-versus-VALUE distinction directly.

Do not edit product code, requirements, graphs, records, evidence, or any other file. Do not commit. Make the smallest targeted change. Match the existing test style.

## Checks

On this PC run only `python -m py_compile` on the changed test files. Do not run pytest or any other Python here.

A fresh full Git clone of `1075fe48` exists on the runner at `/tmp/b103-e4-11-oracle-kimi/tree`. Copy only your changed test files there and run the targeted test with `/home/javiergr/miniconda3/envs/s19ci/bin/python`, `PYTHONDONTWRITEBYTECODE=1`, stdin `/dev/null`, and HOME/XDG/LOCALAPPDATA isolated under `/tmp/b103-e4-11-oracle-kimi/zq_iso_user`. Start the transcript by printing `s19_app.__file__`.

Run:

1. The focused synthetic case, if added.
2. `tests/test_b103_a2l_reader.py::test_r_a2l_read_48_tracked_files_equal_ref`.
3. The whole `tests/test_b103_a2l_reader.py` without `serial_timing`.

Do not run timing tests. Do not write the OS clipboard. Do not use or copy proprietary A2L material. Do not push, merge, reset, or delete branches. Do not modify the pre-existing runner tree `~/work/b103-int11`.

## Report

Report the exact diff summary, test counts, commands and exit codes, and any remaining failure. Do not claim the integration is green from a partial run.
