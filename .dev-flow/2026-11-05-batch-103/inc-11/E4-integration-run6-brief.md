# Inc 11 E4: integration run 6 after the CURVE oracle correction (DeepSeek)

Worktree `C:\Users\<user>\Github\s19_app-b103-inc11-code`, branch `b103-inc11-code`. The orchestrator will supply the final commit containing `1075fe48` plus the test-only CURVE reference correction. Do not edit any product or test file.

## Runner and isolation

Use the Linux runner only. Create a fresh full Git clone of the supplied commit under `/tmp/b103-e4-11-int6/tree`; do not use the stale, dirty `~/work/b103-int11`. Use `/home/<user>/miniconda3/envs/s19ci/bin/python`, `PYTHONDONTWRITEBYTECODE=1`, stdin `/dev/null`, and HOME, XDG_CONFIG_HOME, XDG_CACHE_HOME, XDG_DATA_HOME and LOCALAPPDATA isolated under `/tmp/b103-e4-11-int6/<user>`.

Start every transcript with `s19_app.__file__`. Use `nohup` for long runs, poll by short SSH calls, and kill only by a verified PID if necessary. Do not modify source or tests while a run is active. Record `uptime` before and after timing runs. Do not write the OS clipboard or use proprietary A2L material.

## Runs

Run without `-m serial_timing`, using `-n 8` for the non-timed groups:

- **A — reader:** `tests/test_b103_a2l_reader.py`, including the new CURVE/VALUE reference case.
- **B — Inc 2a regression:** `tests/test_b103_a2l_definition.py` and `tests/test_b103_synth_definitions.py`.
- **C — changed legacy tests:** `tests/test_a2l_multiline_headers.py`, `tests/test_b101_a2l_blocks_and_segments.py`, `tests/test_tui_a2l_issue_recolor.py`, `tests/test_b100_a2l_progress.py`, `tests/test_tui_directionb.py`, and `tests/test_tui_issues_triage_b94.py`.
- **D — laws:** `tests/test_address_census.py`, `tests/test_suite_hygiene.py`, `tests/test_id_registry.py`, `tests/test_engine_unchanged.py`, `tests/test_docs_canon.py`, `tests/test_b101_doc_hygiene.py`, and `tests/test_b101_help_legend_docs.py`.
- **E — timing:** `tests/test_b103_a2l_reader_perf.py` and `tests/test_b103_a2l_definition_perf.py`, one at a time with `-m serial_timing`. R-A2L-READ.52 requires time <= 1.5x and peak memory <= 2x. Run timing only on a quiet host and only after A-D are green.

Save complete transcripts on the runner, then copy them into `inc-11/evidence-e4/` as `int-green6-a.txt`, `int-green6-b.txt`, `int-green6-c.txt`, `int-green6-d.txt`, and `int-green6-e.txt`. The transcript files must include the pytest exit codes. Do not type result counts by hand.

## Report and cleanup

Report pass/fail/skip counts and each failure with its file and cause. Do not claim green from a partial or truncated run. Copy the transcripts into the local worktree but do not commit. Remove only the `/tmp/b103-e4-11-int6*` scratch paths after all evidence has landed. On this PC run only git, ssh/scp and `py_compile`; no pytest or other Python.
