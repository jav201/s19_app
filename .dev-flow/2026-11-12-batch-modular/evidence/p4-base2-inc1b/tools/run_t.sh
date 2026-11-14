#!/usr/bin/env bash
# Targeted run (HT-02/HT-03). Usage: run_t.sh <tree> <out_dir> <workers|0> <timeout_s> <pytest args...>
set -u
TREE="$1"; OUT="$2"; NW="$3"; TO="$4"; shift 4
PY="$HOME/miniconda3/envs/s19ci/bin/python"
ST="$OUT/state"
mkdir -p "$OUT"; rm -rf "$ST" "$OUT/junit.xml" "$OUT/rc" "$OUT/run.txt"
mkdir -p "$ST/home/<iso-home>" "$ST/x/c" "$ST/x/d" "$ST/x/k" "$ST/x/s" "$ST/tmp"
cd "$TREE" || exit 3
XD=""; [ "$NW" != "0" ] && XD="-n $NW --dist loadfile"
{
  echo "TREE_REV: $(git rev-parse HEAD)"
  echo "ARGS: $*"
  echo "LOAD_START: $(cat /proc/loadavg)"
} > "$OUT/run.txt"
timeout "$TO" env -i PATH="/usr/bin:/bin" HOME="$ST/home/<iso-home>" XDG_CONFIG_HOME="$ST/x/c" XDG_DATA_HOME="$ST/x/d" \
  XDG_CACHE_HOME="$ST/x/k" XDG_STATE_HOME="$ST/x/s" TMPDIR="$ST/tmp" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONIOENCODING=utf-8 LANG=C.UTF-8 TERM=xterm-256color \
  "$PY" -c "import sys; sys.path.insert(0,'.'); import s19_app; print(s19_app.__file__); import pytest; sys.exit(pytest.main(['-q','-p','no:cacheprovider','--junitxml','$OUT/junit.xml','-rfE'] + '$XD'.split() + sys.argv[1:]))" "$@" \
  < /dev/null >> "$OUT/run.txt" 2>&1
RC=$?
echo "LOAD_END: $(cat /proc/loadavg)" >> "$OUT/run.txt"
echo "$RC" > "$OUT/rc"
echo "RUN_DONE rc=$RC" >> "$OUT/run.txt"
