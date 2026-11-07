#!/bin/bash
# usage: sec-e5r2-run.sh <script> [args...]  -- isolated env (-I -B), read-only trees, no bytecode writes, no stdin, no display
# E5 security re-review (round 2), batch-103 Inc 2a. Scratch /tmp/b103-e5r2-2a-sec (deleted at the end of the review).
S=/tmp/b103-e5r2-2a-sec
PY="$HOME/miniconda3/envs/s19ci/bin/python"
export HOME=$S/<user> XDG_CONFIG_HOME=$S/<user>/.config XDG_DATA_HOME=$S/<user>/.local/share \
       XDG_CACHE_HOME=$S/<user>/.cache XDG_STATE_HOME=$S/<user>/.local/state LOCALAPPDATA=$S/<user>/lad \
       PYTHONDONTWRITEBYTECODE=1
unset DISPLAY WAYLAND_DISPLAY
mkdir -p "$HOME" "$S/work"
cd "$S"
exec "$PY" -I -B "$@" < /dev/null
