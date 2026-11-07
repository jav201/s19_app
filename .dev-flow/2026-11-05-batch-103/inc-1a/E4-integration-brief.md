# Inc 1a E4 integration GREEN (DeepSeek v4 Pro)

Worktree `C:\Users\jjgh8\Github\s19_app-b103-inc1a-code`, branch `b103-inc1a-code`, HEAD `e719d7fc`. It holds the implementer, the tester and `batch-103` merged together. **Do not edit any product or test file.**

1. **Build the runner tree.**
   - On this PC: `git bundle create <scratchpad>/i1a.bundle e07fb00..b103-inc1a-code`.
   - Pipe it over ssh to cachyos-rtx.
   - There: `git clone -q --shared /home/javiergr/work/s19_app /home/javiergr/work/b103-int1a`, fetch the bundle's `b103-inc1a-code`, and check it out.
   - Use `ssh -o BatchMode=yes javiergr@192.168.1.67 "bash -lc '…'"` and the Python `/home/javiergr/miniconda3/envs/s19ci/bin/python`, as an absolute path.
2. **Run with isolation and Xvfb.**
   - Set HOME, XDG_CONFIG_HOME and LOCALAPPDATA to `/tmp/b103-int1a/zq_iso_user`, with `PYTHONDONTWRITEBYTECODE=1` and stdin `/dev/null`.
   - Run every clipboard test inside `xvfb-run -a`, on a private display. Never use the host display or clipboard.
   - Run:
     - (a) `tests/test_b103_clipboard_core.py tests/test_b103_clipboard_matrix.py tests/test_b103_clipboard_windows.py` (the Windows arms skip);
     - (b) the re-pointed `tests/test_b102_clipboard.py tests/test_loadfilescreen_input.py`;
     - (c) the 7 laws: `test_address_census`, `test_suite_hygiene`, `test_id_registry`, `test_engine_unchanged`, `test_docs_canon`, `test_b101_doc_hygiene`, `test_b101_help_legend_docs`.
   - Save each transcript to `inc-1a/evidence-e4/int-green-{a,b,laws}.txt` in this worktree. Start each with `python -c "import s19_app; print(s19_app.__file__)"`.
3. **The timing RED mutant** (`inc-1a/E3-rulings.md` E3A-03): on a **copy** of the tree, apply the `tkinter.Tcl()` mutant the handoff describes. Run the timed tests. Save the result to `inc-1a/evidence-e4/int-mutant-tcl.txt`.
4. **If a test fails:** read it, and say whether the implementation or the test is at fault, with the line. **Fix nothing.**
5. Delete `/tmp/b103-int1a` at the end. Keep `~/work/b103-int1a` for E5. Kill processes by PID only. On this PC run only git and ssh; run no Python.

**Report (≤ 120 words):** pass/fail counts per run, every failure with its cause, and the mutant result.
