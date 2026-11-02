#!/bin/bash
# usage: run4.sh <outfile> <nodes...>
out="$1"; shift
cd ~/s19fix3
unset NO_COLOR
export PYTHONDONTWRITEBYTECODE=1
{ ~/s19venv/bin/python -c 'import s19_app,sys;print(s19_app.__file__, sys.version)'; timeout 1800 ~/s19venv/bin/python -m pytest -q -p no:cacheprovider "$@"; echo "exit=$?"; } > "$out" 2>&1
tail -5 "$out"
