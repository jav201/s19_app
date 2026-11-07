#!/bin/bash
# usage: run11.sh <mode>   (runs on cachyos-rtx; isolated HOME, no display, stdin closed)
set -u
B=/tmp/b103-e1-11; RH=$HOME; R=$RH/work/s19_app; PY=$RH/miniconda3/envs/s19ci/bin/python
export HOME=$B/zq_iso_user XDG_CONFIG_HOME=$B/zq_iso_user/.config XDG_DATA_HOME=$B/zq_iso_user/.local/share XDG_CACHE_HOME=$B/zq_iso_user/.cache LOCALAPPDATA=$B/zq_iso_user/AppData/Local
unset DISPLAY WAYLAND_DISPLAY
mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$LOCALAPPDATA"
cd $B/scratch
echo "host=$(hostname) date=$(date -Iseconds) clone=$(git -C $R rev-parse HEAD) changed=$(git -C $R status --short | wc -l) HOME=$HOME"
timeout 1500 $PY -I $B/e1-census.py $R $B/scratch "$1" < /dev/null
echo "exit=$? clone_changed_after=$(git -C $R status --short | wc -l)"
