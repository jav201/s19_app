#!/bin/sh
# usage: check.sh <graph basename> THREAD=trace.json ...
CW=/c/Users/jjgh8/AppData/Local/Temp/claude/C--Users-jjgh8-clde/a8feab43-c248-4ccb-86cf-122b894659b2/scratchpad/cw26/tools
O=C:/Users/jjgh8/Github/s19_app/.dev-flow/design/codewire-audit-2026-10-23/data
g=$1; shift
args=""; for t in "$@"; do args="$args --trace $t"; done
cd C:/Users/jjgh8/Github/s19_app-cwaudit-data/cwaudit
PYTHONDONTWRITEBYTECODE=1 /c/Users/jjgh8/anaconda3/envs/s19env/python.exe $CW/codewire_examples.py --graph $O/$g.md $args --out $O/examples-$g.md
grep "drift |\|no_anchor |\|node_not_run |" $O/examples-$g.md
