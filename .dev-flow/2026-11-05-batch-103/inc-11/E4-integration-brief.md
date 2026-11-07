# Inc 11 E4: integration GREEN (DeepSeek v4 Pro)

Worktree `C:\Users\jjgh8\Github\s19_app-b103-inc11-code`, branch `b103-inc11-code`, HEAD `27944331`: the implementer `d8ddd2a5` plus the tester `19768229`, on `batch-103` with Inc 2a. **Do not edit any product or test file.**

1. **Runner tree.**
   - Create a bundle `e07fb00..b103-inc11-code` in the scratchpad and pipe it to cachyos-rtx.
   - On the runner: `git clone -q --shared /home/javiergr/work/s19_app /home/javiergr/work/b103-int11`, fetch the bundle's `b103-inc11-code`, and check it out.
   - ssh form: `ssh -o BatchMode=yes javiergr@192.168.1.67 "bash -lc '…'"`.
   - Python: `/home/javiergr/miniconda3/envs/s19ci/bin/python`, as an absolute path.
2. **Isolation.** Set HOME, XDG_CONFIG_HOME and LOCALAPPDATA to `/tmp/b103-int11/zq_iso_user`. Set `PYTHONDONTWRITEBYTECODE=1` and use stdin `/dev/null`.
3. **Runs.** Start each transcript with `python -c "import s19_app; print(s19_app.__file__)"`. Save every transcript under `inc-11/evidence-e4/` in this worktree.
   - **(a) The tester's files.** Get them with `git show --stat 19768229`. Run them without `-m serial_timing`. Save as `int-green-a.txt`.
   - **(b) Inc 2a's tests**, because Inc 11 edits `a2l_definition.py`: `tests/test_b103_a2l_definition.py` and `tests/test_b103_synth_definitions.py`. Save as `int-green-b.txt`.
   - **(c) The 7 laws:** `test_address_census`, `test_suite_hygiene`, `test_id_registry`, `test_engine_unchanged`, `test_docs_canon`, `test_b101_doc_hygiene` and `test_b101_help_legend_docs`. Save as `int-green-laws.txt`.
   - **(d) The timed tests, one at a time with `-m serial_timing`:** the tester's perf arms and `tests/test_b103_a2l_definition_perf.py`. Record the host load (`uptime`) before and after. READ.52 must be ≤ 1.5× on the 19.8 MB file. Save as `int-green-perf.txt`.
4. **On a failure:** read the failing test and say whether the implementation or the test is at fault, with the line. **Fix nothing.**
5. **Cleanup.** Delete `/tmp/b103-int11` and keep `~/work/b103-int11` for E5. Kill processes by PID only. On this PC, run only git and ssh, and no Python.

**Report** (≤ 120 words): pass/fail counts per run, each failure with its cause, and the READ.52 ratio.

## Run 2 (the first run timed out at 90 min: the ssh link was cut during (a), and (d) was left running)

- **Never hold a long run on one ssh link.** On the runner, start each run with `nohup … > /tmp/b103-int11/<run>.log 2>&1 &`, record its PID, poll with a short ssh every few minutes, and fetch the log when it ends. Use `-n 8` (xdist) for (a), (b) and (c).
- **Order:** run (a) first. The partial transcript of run 1 shows many failures, so classify every failure (implementation or test, with the line) before you run (d). Run (d) only if time remains, and only for READ.52 plus the tester's perf file.
- Save every transcript as `int-green2-*.txt`. In the report, list each failing test id with its one-line cause.
