#!/bin/bash
# usage: run.sh <script> [args...]  -- isolated env, read-only trees, no bytecode writes, no stdin, no display
S=/tmp/b103-e3r4-3-S
PY="$HOME/miniconda3/envs/s19ci/bin/python"
export HOME=$S/zq_iso_user XDG_CONFIG_HOME=$S/zq_iso_user/.config XDG_DATA_HOME=$S/zq_iso_user/.local/share XDG_CACHE_HOME=$S/zq_iso_user/.cache LOCALAPPDATA=$S/zq_iso_user/lad PYTHONDONTWRITEBYTECODE=1
unset DISPLAY WAYLAND_DISPLAY
mkdir -p $HOME $S/work
cd $S
exec "$PY" -I "$@" < /dev/null
