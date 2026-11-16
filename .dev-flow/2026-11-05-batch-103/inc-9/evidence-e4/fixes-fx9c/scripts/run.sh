#!/bin/bash
# FX9c runner: run.sh <tree> <out> <pytest args...>; HT-02 env; HOME basename read from RUNNER_HOME_NAME (HT-11).
T=$1; O=$2; shift 2
S=~/work/zq-fx9c
mkdir -p $S/home/$RUNNER_HOME_NAME $S/x/config $S/x/cache $S/x/data $S/tmp $S/out
cd $T
E="env -i PATH=/usr/bin:/bin HOME=$S/home/$RUNNER_HOME_NAME XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=. FX9C_NOBRACKET=${FX9C_NOBRACKET:-}"
PY=~/miniconda3/envs/s19ci/bin/python
{ echo "load before: $(cat /proc/loadavg)"; $E $PY -c "import s19_app;print(s19_app.__file__)"; $E timeout ${TMO:-300} $PY -m pytest -p no:cacheprovider "$@" < /dev/null; echo "rc=$?"; echo "load after: $(cat /proc/loadavg)"; } > $S/out/$O 2>&1
