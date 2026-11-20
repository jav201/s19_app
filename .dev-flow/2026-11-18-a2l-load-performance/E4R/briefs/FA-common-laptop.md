# Front A — common delta to `frontB\FB-common.md` (alp units on the laptop)

Every Front A worker brief = the text of `frontB\FB-common.md` + this delta + the unit brief, concatenated in that order. Where this delta and FB-common disagree, **this delta wins**.

## Tree and host (replaces FB-common "Tree and environment")
- **Host:** the CachyOS laptop (HT-01 reference host; the orchestrator gives the address at launch, records write `<host>`). Shell is fish: the launcher wraps commands in `bash -lc '…'`.
- **Tree:** a clone of the bundle `~/work/zq-fa/fa.bundle`, branch `alp-e4r`, checked out as branch `work`, in `~/work/zq-fa/<UNIT>/repo`.
  - **HEAD is the sha written in your unit brief** (`git rev-parse HEAD` must print it; if not, STOP).
  - The unit folder is `..` (`REPORT.md`, `scratch/`, `state/`).
- **Python:** `/data/miniconda3/envs/s19ci/bin/python` (3.11). Never `~/miniconda3/...` (that path is rtx's), never the system python.
- **Every pytest** (one line, from the tree root):
  `S=$(realpath ../state); mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 300 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 /data/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q <nodes> < /dev/null`
  - Before the first run print `s19_app.__file__` with the same env (HT-03): it must be inside `./s19_app`.

## Timing (stricter than FB-common)
- **Never decide a timing result.** The laptop is the reference host and is quiet only when the orchestrator says so.
  - You may run a `serial_timing` node only where your brief says so: to show RED under a negative control, or to check that a changed node executes.
  - Record such a GREEN as "indicative, not decided". The orchestrator re-runs every timing node serially on the quiet host.
- **Never run a node marked `slow`** (case_06 arms, minutes each) unless your brief names it.
- **A timeout (exit 124) is TIMEOUT**, neither PASS nor FAIL.
- **No "flaky" label** without N ≥ 10 runs and a rate (HT-07). You will not have that budget, so report the observation instead.

## Records and requirements
- **The batch folder is `.dev-flow/2026-11-18-a2l-load-performance/`.**
  - Never edit anything under `inc-1/`, `inc-2/`, `inc-3/`, `PLAN.md`, `interfaces.md`, or any inherited evidence (PP-06: fix forward).
  - New records go under `E4R/` only when your brief says so.
- **The requirement rows of this front are in `E4R/01-requirements.md`** (written by FA-REQ). The ids are R-A2L-REFRESH.033/.034/.037/.040–.042/.049–.053 and R-A2L-DEF.162–.168.
  - A test you change cites the E4R id in its docstring.
  - Never cite a graph example (e.g. `.140/11`) as the row.
- **Privacy (PP-03):** never write user names, host names, IPs or home paths in any file. Write `~`, `<user>`, `<host>`.

## Hard rules repeated
- No agent edits `~/.claude/skills` (not on this host; the rule stands anyway).
- No git writes of any kind (commit, add, stash, reset, checkout of files, worktree). LF only, UTF-8, no BOM.
- Edit only the files your brief lists. Keep every test function name and parametrize id (registry keys).
  - A new test function is allowed only where the brief orders it.
  - Never `skip`, `xfail`, reruns, fixed sleeps or loosened assertions.
- **Negative control for every changed row** (FB-common rule 6): make a scratch copy `cp -a . ../scratch/nc-<row>`, apply the brief's mutation, run only that node, and paste the RED line. Delete `../scratch/nc-*` after the row.
- `../REPORT.md` is appended after each row, never rewritten. Its last line is `UNIT_DONE <UNIT>`.
- Never `pip install`/`uninstall` (or `conda`) anything: the python env is shared by every worker. pytest imports `s19_app` from the tree you run it in (`pyproject.toml` `pythonpath = ["."]`, checked 2026-11-19), so run each negative control from inside its scratch copy (`cd ../scratch/nc-<row>`). If a mutation seems not to take effect, STOP and report; do not touch the env.

## Orchestrator notes (not for the worker)
- **Launcher.** Copy `frontB\launch_unit.sh` to the laptop as `~/work/zq-fa/launch_unit.sh`, with `B=$HOME/work/zq-fa`, bundle `fa.bundle`, branch `alp-e4r`.
  - FA-0 checks `command -v pi` on the laptop. If `pi` is absent, run the DeepSeek units on rtx with the same bundle, and keep the laptop for FA-0, M1, M2 and FA-TICK only.
  - At most 2 workers at a time on the laptop (MD-03). No worker runs during M1, M2, FA-0 or FA-TICK.
- **Before launch (HT-13):** write the HEAD sha into the brief, grep the brief's "facts" against that tree, and rebuild `fa.bundle` from the integrated tip.
- **After each unit:** run CHK-ds (a DeepSeek session that did not write the unit), do your own intent review, integrate onto `alp-e4r` with a commit plus one `E4R/RECORD.md` line plus one `steps.log` line (time from `date`, model `[deepseek-v4-pro · high]` etc.).
