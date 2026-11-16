#!/bin/bash
# Inc 10 E5 (X10) runner wrapper: HT-02 isolated env, HT-03 s19_app.__file__ first.
# usage: run.sh <tree dir under the scratch> <log name> <pytest args...>
# RUNNER_HOME_NAME must be exported: the HT-02 HOME basename, read from the env
# so no record spells it (HT-11).
set -u
S=~/work/zq-x10
T=$1; shift; L=$1; shift
: "${RUNNER_HOME_NAME:?export RUNNER_HOME_NAME}"
mkdir -p "$S/home/$RUNNER_HOME_NAME" "$S/x/config" "$S/x/cache" "$S/x/data" "$S/tmp" "$S/logs"
cd "$S/$T" || exit 2
E=(env -i PATH=/usr/bin:/bin HOME="$S/home/$RUNNER_HOME_NAME" XDG_CONFIG_HOME="$S/x/config" XDG_CACHE_HOME="$S/x/cache" XDG_DATA_HOME="$S/x/data" TMPDIR="$S/tmp" PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=.)
PY=~/miniconda3/envs/s19ci/bin/python
{
  "${E[@]}" "$PY" -c "import s19_app;print(s19_app.__file__)"
  echo "tree: $T  $(cat "$S/$T/.x10-rev" 2>/dev/null)"
  echo "uptime: $(uptime)"
  echo "+ pytest -p no:cacheprovider $*"
  "${E[@]}" timeout 300 "$PY" -m pytest -p no:cacheprovider "$@" < /dev/null
  echo "RC=$?"
} > "$S/logs/$L.txt" 2>&1
tail -2 "$S/logs/$L.txt"
