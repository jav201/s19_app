#!/bin/bash
# Caller exports RUNNER_HOME_NAME = the HT-02 HOME basename (kept out of the repo, PP-03).
# usage: run.sh <logname> <pytest args...>   (runs in ~/work/zq-mu10/tree)
S=$HOME/work/zq-mu10
L=$1; shift
cd $S/tree
{
echo "# $(date -u +%FT%TZ) load: $(cut -d' ' -f1-3 /proc/loadavg)"
env -i PATH=/usr/bin:/bin HOME=$S/home/$RUNNER_HOME_NAME XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=. ~/miniconda3/envs/s19ci/bin/python -c "import s19_app;print(s19_app.__file__)"
timeout 300 env -i PATH=/usr/bin:/bin HOME=$S/home/$RUNNER_HOME_NAME XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=. ~/miniconda3/envs/s19ci/bin/python -m pytest -p no:cacheprovider -n 2 -q -rf "$@" < /dev/null
echo "# rc=$? $(date -u +%FT%TZ)"
} > $S/logs/$L.txt 2>&1
