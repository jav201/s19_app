#!/bin/bash
# usage: run.sh TREE OUT [pytest args...]   (HT-02/HT-03 isolated pytest, one file or node set)
# RUNNER_HOME_NAME carries the HOME basename (HT-11: never spelled in this script or in records).
S=$HOME/work/zq-x8b
T=$1; OUT=$2; shift 2
PY=${S19_PY:-$HOME/miniconda3/envs/s19ci/bin/python}
H="$S/home/${RUNNER_HOME_NAME:?set RUNNER_HOME_NAME}"
mkdir -p "$H" "$S/x/config" "$S/x/data" "$S/x/cache" "$S/x/state" "$S/tmp"
cd "$T" || exit 9
ENVV=(env -i PATH=/usr/bin:/bin HOME="$H" XDG_CONFIG_HOME="$S/x/config" XDG_DATA_HOME="$S/x/data"
      XDG_CACHE_HOME="$S/x/cache" XDG_STATE_HOME="$S/x/state" TMPDIR="$S/tmp"
      PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8)
{
  echo "## uptime: $(uptime)"
  echo "## date: $(date -u +%FT%TZ)  head: $(git rev-parse --short=8 HEAD)"
  "${ENVV[@]}" "$PY" -c 'import sys; sys.path.insert(0, "."); import s19_app; print("## s19_app.__file__ =", s19_app.__file__)'
  "${ENVV[@]}" timeout 300 "$PY" -m pytest -p no:cacheprovider -q "$@" < /dev/null
  echo "## rc=$?"
  echo "## end: $(date -u +%FT%TZ)  uptime: $(uptime)"
} > "$OUT" 2>&1
