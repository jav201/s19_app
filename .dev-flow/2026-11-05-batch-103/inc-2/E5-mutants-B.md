# E5 mutant unit B — Inc 2a (the 2a rows from R-A2L-DEF.59 up (.59 … .151)), on HEAD `26d3e309` (DeepSeek v4 Pro)

**Rules:** `C:\Users\jjgh8\Github\s19_app-b103\.dev-flow\2026-11-05-batch-103\design\E5-brief-common.md`, with N = `2` and role `mutB`. Read it first.

**Task.** Take the 2a rows from R-A2L-DEF.59 up (.59 … .151) of `inc-2/01-requirements.md`. Use only the rows the "Split (amendment A2)" section gives to 2a; skip the 2b-only rows and the 2b arms.
- For each row, take its **Negative control** cell. Where `E3-rulings.md` or `E5-rulings.md` name a second control, take both.
- The cell describes a mutation of the product. Apply it to a copy of the product file it names, usually `s19_app/tui/a2l_definition.py` and for the synth rows `tools/synth/make_release_case.py`.
- Run the row's tests. The mutant is **killed** if at least one of the row's tests fails, and **survived** if all of them pass.

**How (all on cachyos-rtx; never on this PC):**
1. Once: `cp -a /home/javiergr/work/b103-int2a /tmp/b103-e5-2-mutB/base`. Never edit `~/work/b103-int2a`.
2. For each mutant `M-<row>` (a second control is `M-<row>b`):
   - `cp -a /tmp/b103-e5-2-mutB/base /tmp/b103-e5-2-mutB/M-<row>`.
   - Edit only the product file there, with the smallest edit that realises the control. Keep a unified diff: `git -C … diff`.
   - Run `<python> -m pytest -q -p no:cacheprovider <the row's test file> -k "<the row's test ids>"`. Find the ids from the Tests column of `02-test-cases.md`.
   - Run perf rows (`tests/test_b103_a2l_definition_perf.py`, `-m serial_timing`) serially, one at a time.
   - The Python is `/home/javiergr/miniconda3/envs/s19ci/bin/python`, with `-I` where you run scripts. Use `PYTHONDONTWRITEBYTECODE=1`, and set HOME / XDG_* / LOCALAPPDATA to a fresh dir named `zq_iso_user`.
   - Delete each mutant tree when its run ends: `/tmp` is a shared 16 GB tmpfs.
3. For each mutant, save the diff and the pytest tail in `/tmp/b103-e5-2-mutB/out/M-<row>.txt`. At the end, copy `out/` back to `inc-2/evidence-e5/mutants-B/` in this worktree: `ssh … "bash -lc 'tar c -C /tmp/b103-e5-2-mutB out'" | tar x -C <local dir>`. Then delete `/tmp/b103-e5-2-mutB`.
4. Write `inc-2/evidence-e5/mutant-table-B.md` with one row per mutant:
   - the id;
   - the requirement row;
   - the control as written;
   - the edit made, in one line;
   - the tests run;
   - the result (killed / survived);
   - the failing test id(s).

   When a control cannot be realised as written, write `not realisable: <why>`. Never invent another control.

Do not change any test or record. Kill runner processes by PID only, never with `pkill -f`. Write one start line and one end line in `inc-2/steps.log`.

**Report (≤ 150 words):** the killed / survived / not realisable counts, each survivor with one line, and the time taken.
