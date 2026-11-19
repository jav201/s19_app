# Front B — common worker rules (DeepSeek v4-pro, one unit per session)

You fix ONE unit of the s19_app "G3 fix round". Your unit brief (attached after this text) names the root cause, the rows, the files you may edit and the nodes. The diagnosis is FIXED: it comes from an independent review and was re-checked against a RED baseline on this host. Do not re-diagnose beyond what a row asks; if the code contradicts the brief, STOP that row and report it (do not choose).

## Tree and environment (Linux host, read carefully)
- Your tree is the current directory: a git clone, branch `work`, HEAD = `main` 3afebf90. The unit folder is `..` (it holds `REPORT.md`, `scratch/`, `state/`).
- Python with the project's dependencies: `~/miniconda3/envs/s19ci/bin/python` (3.11). Never the system python.
- EVERY pytest/python that imports `s19_app` uses exactly this (one line), from the tree root:
  `S=$(realpath ../state); mkdir -p $S/home/runner_iso $S/tmp $S/x; timeout 300 env -i PATH=/usr/bin:/bin HOME=$S/home/runner_iso XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q <nodes> < /dev/null`
- Run only the nodes/files of your unit, `-n 0` or `-n 4` as the brief says. NEVER the full suite, never the law files (an independent tester runs them), never `-x` on a whole directory.
- A `timeout` exit (124) is not a PASS and not a FAIL: record it as TIMEOUT and move on.

## Hard rules
1. Edit ONLY the files your unit lists. Never `s19_app/` product code unless your unit explicitly lists a product file.
2. No git writes at all (no commit, add, stash, reset, checkout of files, worktree). LF line endings, UTF-8, no BOM.
3. Keep every test function name and parametrize id exactly (node ids are keys in the trace registry). Keep each test's intent; you may update docstring wording that names an old seam.
4. Never add `skip`, `skipif`, `xfail`, reruns, `--flaky`, sleeps or wait loops with fixed delays. Waiting for a worker or a deferred callback uses the app's own completion signal or a bounded poll on the observable effect (state, log line, painted text), with the bound stated.
5. Never loosen an assertion to make it pass. A re-pin moves the test to the CURRENT seam that implements the SAME requirement row; the assertion keeps its meaning.
6. NEGATIVE CONTROL for every row you change (mandatory): `cp -a . ../scratch/nc-<row>`; in the copy apply a one-line product mutation that removes the guard the row verifies (the brief suggests one; if you pick another, say why); run ONLY that node in the copy; paste the RED assertion line. A changed test that stays GREEN under its mutation is a defect: fix the test until it goes RED. Delete `../scratch/nc-*` when the row is done.
7. Do not edit anything under `~/.claude/skills` (it is not on this host anyway; the rule stands).
8. Records you write never contain user names, host names, IPs or home paths: write `~`, `<user>`, `<host>`, `<runner-home>`.

## Report — `../REPORT.md`, appended after EACH row (never rewrite or delete earlier lines)
Header once: unit id, HEAD sha (`git rev-parse HEAD`), start time from `date`.
Per row: `| row | file:function | change (one line) | negative-control mutation (file:line, one line) | command | RED line under mutation | GREEN result after change | OPEN? |`
Then sections `## Deviations` (each with evidence: grep/command output) and `## Open questions`.
At the end: `git diff --stat`, `git diff | grep -c $'\r'` (must be 0), and the final run of all your unit's files with its summary line. Print `UNIT_DONE <unit>` as the last line of REPORT.md.
