#!/bin/bash
# Caller exports RUNNER_HOME_NAME = the HT-02 HOME basename (kept out of the repo, PP-03).
# usage: run.sh <tree-dir-name> <label> <pytest args...>
S=$HOME/work/zq-e4-10-int
TN=$1; T=$S/$1; L=$2; shift 2
mkdir -p $S/home/$RUNNER_HOME_NAME $S/x/config $S/x/cache $S/x/data $S/tmp $S/logs
cd $T || exit 9
E="env -i PATH=/usr/bin:/bin HOME=$S/home/$RUNNER_HOME_NAME XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=."
PY=$HOME/miniconda3/envs/s19ci/bin/python
{
echo "== $L | tree $TN | $(date -u +%Y-%m-%dT%H:%M:%SZ) | load: $(cut -d' ' -f1-3 /proc/loadavg)"
$E $PY -c "import s19_app;print('s19_app.__file__ =', s19_app.__file__)"
$E timeout 300 $PY -m pytest -p no:cacheprovider "$@" < /dev/null
echo "rc=$?"
} > $S/logs/$L.txt 2>&1
tail -n 25 $S/logs/$L.txt
