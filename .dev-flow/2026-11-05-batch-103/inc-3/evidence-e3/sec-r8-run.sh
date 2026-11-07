#!/bin/bash
# usage: sec-r8-run.sh <script> [args...]  -- isolated env (-I -B), read-only trees, no bytecode writes, no stdin, no display
S=/tmp/b103-e3r8-3-S
PY="$HOME/miniconda3/envs/s19ci/bin/python"
export HOME=$S/<user> XDG_CONFIG_HOME=$S/<user>/.config XDG_DATA_HOME=$S/<user>/.local/share XDG_CACHE_HOME=$S/<user>/.cache LOCALAPPDATA=$S/<user>/lad PYTHONDONTWRITEBYTECODE=1
unset DISPLAY WAYLAND_DISPLAY
mkdir -p $HOME $S/work
cd $S
echo "pid $$" >&2
exec "$PY" -I -B "$@" < /dev/null
