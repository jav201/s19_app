#!/bin/bash
# usage: addenda-run.sh <mode>
S=/tmp/b103-e3a-4
cd "$S" || exit 1
export HOME=$S/home XDG_CONFIG_HOME=$S/home/.config XDG_DATA_HOME=$S/home/.local/share XDG_CACHE_HOME=$S/home/.cache LOCALAPPDATA=$S/home/localappdata
export PILOT_DIR=$S/pilot REPO=/home/javiergr/work/s19_app OUT=$S/out EVID_DIR=$S AS_CAP_GIB=8
unset DISPLAY WAYLAND_DISPLAY
PY=/home/javiergr/miniconda3/envs/s19ci/bin/python
out=addenda-$1-transcript.txt
timeout 1800 $PY -s addenda-probe.py "$1" > "$out" 2>&1 < /dev/null
echo "exit $? -> $out"
