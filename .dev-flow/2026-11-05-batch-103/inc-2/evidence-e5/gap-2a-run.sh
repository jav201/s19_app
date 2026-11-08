#!/bin/bash
# usage: gap-2a-run.sh <script> [args...]  -- isolated env, read-only tree copy, no bytecode writes, no stdin, no display
S=/tmp/b103-e5g-2a
PY="/home/<user>/miniconda3/envs/s19ci/bin/python"
export HOME=$S/<user> XDG_CONFIG_HOME=$S/<user>/.config XDG_DATA_HOME=$S/<user>/.local/share XDG_CACHE_HOME=$S/<user>/.cache LOCALAPPDATA=$S/<user>/lad PYTHONDONTWRITEBYTECODE=1
unset DISPLAY WAYLAND_DISPLAY
mkdir -p $HOME $S/work
cd $S
exec "$PY" -I "$@" < /dev/null
