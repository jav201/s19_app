#!/bin/bash
# usage: run.sh <script> [args...]  -- isolated env, read-only trees, no bytecode writes, no stdin, no display
S=/tmp/b103-e3r2-3-S
export HOME=$S/<user> XDG_CONFIG_HOME=$S/<user>/.config XDG_DATA_HOME=$S/<user>/.local/share XDG_CACHE_HOME=$S/<user>/.cache LOCALAPPDATA=$S/<user>/lad PYTHONDONTWRITEBYTECODE=1
unset DISPLAY WAYLAND_DISPLAY
mkdir -p $HOME $S/work
cd $S
exec ~/miniconda3/envs/s19ci/bin/python -I "$@" < /dev/null
