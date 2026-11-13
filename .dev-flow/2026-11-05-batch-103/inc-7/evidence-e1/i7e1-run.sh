#!/bin/bash
# i7e1-run.sh -- run one Inc 7 E1 pilot on the runner in an isolated environment (HT-02, HT-03).
# usage: bash i7e1-run.sh <script> <transcript>
S=$HOME/work/zq-i7/s
R=$HOME/work/zq-i7/repo
cd "$R" || exit 9
timeout 900 env -i PATH=/usr/bin:/bin HOME=$S/home/runner_iso XDG_CONFIG_HOME=$S/x/config \
  XDG_DATA_HOME=$S/x/data XDG_CACHE_HOME=$S/x/cache LOCALAPPDATA=$S/x/data TMPDIR=$S/tmp \
  PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 \
  $HOME/miniconda3/envs/s19ci/bin/python -B "$HOME/work/zq-i7/ev/$1" "$R" "$S/out" < /dev/null > "$HOME/work/zq-i7/ev/$2" 2>&1
echo "rc=$?" >> "$HOME/work/zq-i7/ev/$2"
