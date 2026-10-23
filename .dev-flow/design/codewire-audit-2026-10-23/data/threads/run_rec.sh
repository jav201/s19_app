#!/bin/sh
# usage: run_rec.sh <test file or nodeid> <trace out> [CW_MAX]
WT=C:/Users/jjgh8/Github/s19_app-cwaudit-data
CW=C:/Users/jjgh8/AppData/Local/Temp/claude/C--Users-jjgh8-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/cw26/tools
cd $WT
unset NO_COLOR
PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH="$CW;$WT/cwaudit;$WT" CW_GRAPHS="$WT/cwaudit/rec-nodes.md" CW_OUT="$WT/$2" CW_MAX="${3:-6}" \
  /c/Users/jjgh8/anaconda3/envs/s19env/python.exe -m pytest -p cw_record_plugin -p no:cacheprovider -q -s "$1" 2>&1 | tail -${4:-60}
