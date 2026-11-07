#!/bin/bash
# usage: run.sh <mode> [hashseed]
S=/tmp/b103-e3r2-4-security
cd "$S" || exit 1
export HOME=$S/home XDG_CONFIG_HOME=$S/home/.config XDG_DATA_HOME=$S/home/.local/share XDG_CACHE_HOME=$S/home/.cache LOCALAPPDATA=$S/home/<localappdata>
export PILOT_DIR=$S/pilot REPO=/home/<user>/work/s19_app OUT=$S/out EVID_DIR=$S AS_CAP_GIB=8
unset DISPLAY WAYLAND_DISPLAY
PY=/home/<user>/miniconda3/envs/s19ci/bin/python
if [ -n "$2" ]; then export PYTHONHASHSEED=$2; out=sec-r2-$1-$2-transcript.txt; else out=sec-r2-$1-transcript.txt; fi
timeout 1800 $PY -s sec-r2-probe.py "$1" > "$out" 2>&1 < /dev/null
echo "exit $? -> $out"
