#!/bin/bash
# usage: sec-r3-run.sh <script> [args...]  -- isolated env (HOME basename <user>), read-only clone and corpus,
# no bytecode writes, no DISPLAY, closed stdin, 8 GB address-space cap, 1 h timeout. The runner account's home is
# passed as B103_RUNNER_HOME (so no account path is written into a script or a transcript).
S=/tmp/b103-e3r3-11-S
export B103_RUNNER_HOME="$HOME"
PY="$HOME/miniconda3/envs/s19ci/bin/python"
export HOME=$S/<user> XDG_CONFIG_HOME=$S/<user>/.config XDG_DATA_HOME=$S/<user>/.local/share XDG_CACHE_HOME=$S/<user>/.cache LOCALAPPDATA=$S/<user>/lad PYTHONDONTWRITEBYTECODE=1
unset DISPLAY WAYLAND_DISPLAY
mkdir -p $HOME $S/work
cd $S
ulimit -v 8000000
exec timeout 3600 "$PY" -I "$@" < /dev/null
