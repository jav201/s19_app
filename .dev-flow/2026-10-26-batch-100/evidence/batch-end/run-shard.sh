#!/bin/bash
# usage: run-shard.sh N
S=<HOME>/AppData/Local/Temp/claude/C--Users-<USER>-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad
N=$1; mkdir -p $S/fb$N/lad
cd $S/full
{ git rev-parse --short HEAD; env -u NO_COLOR PYTHONPATH=. <HOME>/anaconda3/envs/s19env/python.exe -c "import s19_app;print(s19_app.__file__)";
timeout 21600 env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=. LOCALAPPDATA=$S/fb$N/lad <HOME>/anaconda3/envs/s19env/python.exe -m pytest -p no:cacheprovider -q -rfE --tb=line --basetemp=$S/fb$N/bt $(cat $S/shard$N.txt); echo "exit=$?"; } > $S/full-shard$N.log 2>&1
