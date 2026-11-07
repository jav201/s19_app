#!/bin/bash
# usage: sec-e5-run.sh <script> [args...]  -- isolated env (-I -B), read-only trees, no bytecode writes, no stdin, no display
# E5 security review, batch-103 Inc 2a. Scratch /tmp/b103-e5-2a-sec (deleted at the end of the review).
S=/tmp/b103-e5-2a-sec
PY="$HOME/miniconda3/envs/s19ci/bin/python"
export HOME=$S/zq_iso_user XDG_CONFIG_HOME=$S/zq_iso_user/.config XDG_DATA_HOME=$S/zq_iso_user/.local/share \
       XDG_CACHE_HOME=$S/zq_iso_user/.cache XDG_STATE_HOME=$S/zq_iso_user/.local/state LOCALAPPDATA=$S/zq_iso_user/lad \
       PYTHONDONTWRITEBYTECODE=1
unset DISPLAY WAYLAND_DISPLAY
mkdir -p "$HOME" "$S/work"
cd "$S"
exec "$PY" -I -B "$@" < /dev/null
