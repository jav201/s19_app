#!/bin/bash
# X10 probe runner: HT-02 env, s19_app.__file__ first. RUNNER_HOME_NAME from the env (HT-11).
S=~/work/zq-x10; cd $S/exact || exit 2
mkdir -p $S/probe-scratch
E=(env -i PATH=/usr/bin:/bin HOME="$S/home/$RUNNER_HOME_NAME" XDG_CONFIG_HOME="$S/x/config" XDG_CACHE_HOME="$S/x/cache" XDG_DATA_HOME="$S/x/data" TMPDIR="$S/tmp" PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=.)
PY=~/miniconda3/envs/s19ci/bin/python
{ "${E[@]}" $PY -c "import s19_app;print(s19_app.__file__)"; echo "tree: $(cat .x10-rev)"; "${E[@]}" timeout 300 $PY x10_probe.py $S/probe-scratch < /dev/null; echo "RC=$?"; } > $S/logs/probe.txt 2>&1
cat $S/logs/probe.txt
