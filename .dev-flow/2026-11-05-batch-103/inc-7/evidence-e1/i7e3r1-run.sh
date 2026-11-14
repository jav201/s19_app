#!/bin/bash
# RUNNER_HOME_NAME: basename of the isolated HOME (HT-02), set by the caller; not spelled in records (HT-11).
# i7e3r1-run.sh -- run one Inc 7 E3R1 tool on the runner in an isolated environment (HT-02, HT-03).
# usage: bash i7e3r1-run.sh <transcript> <python args...>   (cwd = the exact clone)
S=$HOME/work/zq-e3r1-7/s
R=$HOME/work/zq-e3r1-7/repo
OUTF=$HOME/work/zq-e3r1-7/ev/$1
shift
mkdir -p "$S/home/${RUNNER_HOME_NAME}" "$S/x/config" "$S/x/data" "$S/x/cache" "$S/tmp" "$S/out"
cd "$R" || exit 9
{ echo "uptime before: $(uptime)"; } > "$OUTF"
timeout 900 env -i PATH=/usr/bin:/bin HOME=$S/home/${RUNNER_HOME_NAME} XDG_CONFIG_HOME=$S/x/config \
  XDG_DATA_HOME=$S/x/data XDG_CACHE_HOME=$S/x/cache LOCALAPPDATA=$S/x/data TMPDIR=$S/tmp \
  PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 \
  $HOME/miniconda3/envs/s19ci/bin/python -B "$@" < /dev/null >> "$OUTF" 2>&1
echo "rc=$?" >> "$OUTF"
echo "uptime after: $(uptime)" >> "$OUTF"
