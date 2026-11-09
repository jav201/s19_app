#!/bin/bash
# usage: run11.sh <mode>   (runs on <runner>; isolated HOME, no display, stdin closed)
set -u
B=/tmp/b103-e1-11; RH=$HOME; R=$RH/work/s19_app; PY=$RH/miniconda3/envs/s19ci/bin/python
export HOME=$B/<user> XDG_CONFIG_HOME=$B/<user>/.config XDG_DATA_HOME=$B/<user>/.local/share XDG_CACHE_HOME=$B/<user>/.cache LOCALAPPDATA=$B/<user>/AppData/Local
unset DISPLAY WAYLAND_DISPLAY
mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$LOCALAPPDATA"
cd $B/scratch
echo "host=$(hostname) date=$(date -Iseconds) clone=$(git -C $R rev-parse HEAD) changed=$(git -C $R status --short | wc -l) HOME=$HOME"
timeout 1500 $PY -I $B/e1-census.py $R $B/scratch "$1" < /dev/null
echo "exit=$? clone_changed_after=$(git -C $R status --short | wc -l)"
