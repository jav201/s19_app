#!/bin/bash
# usage: run.sh <tree> <out> <n> <timeout> [extra env K=V ...] -- <pytest args>
# HOME basename comes from RUNNER_HOME_NAME (HT-02 value, set by the caller; HT-11: never spelled in records)
S=~/work/zq-fx9
tree=$1; out=$2; n=$3; t=$4; shift 4
extra=()
while [ "$1" != "--" ]; do extra+=("$1"); shift; done
shift
mkdir -p "$S/home/$RUNNER_HOME_NAME" "$S/x/config" "$S/x/cache" "$S/x/data" "$S/tmp"
cd "$S/$tree" || exit 9
E=(env -i PATH=/usr/bin:/bin HOME="$S/home/$RUNNER_HOME_NAME" XDG_CONFIG_HOME="$S/x/config" XDG_CACHE_HOME="$S/x/cache" XDG_DATA_HOME="$S/x/data" TMPDIR="$S/tmp" PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=. "${extra[@]}")
{
  echo "# uptime before: $(cat /proc/loadavg)"
  "${E[@]}" ~/miniconda3/envs/s19ci/bin/python -c "import s19_app;print('s19_app.__file__ =', s19_app.__file__)"
  "${E[@]}" timeout "$t" ~/miniconda3/envs/s19ci/bin/python -m pytest -p no:cacheprovider -n "$n" "$@" < /dev/null
  echo "# rc=$?"
  echo "# uptime after: $(cat /proc/loadavg)"
} > "$S/out/$out" 2>&1
