#!/usr/bin/env bash
# E3 round-3 security runner, batch-103 Inc 1a: headless, no clipboard, isolated HOME.
set -u
S=/tmp/b103-e3r3-1a-security
PY="$HOME/miniconda3/envs/s19ci/bin/python"
SRC="$HOME/work/s19_app"
mkdir -p "$S/home" "$S/xdg/config" "$S/xdg/cache" "$S/xdg/data" "$S/xdg/runtime" "$S/tmp" "$S/localappdata"
chmod 700 "$S/xdg/runtime"
cd "$S"
env -u DISPLAY -u WAYLAND_DISPLAY -u NO_COLOR \
  HOME="$S/home" XDG_CONFIG_HOME="$S/xdg/config" XDG_CACHE_HOME="$S/xdg/cache" \
  XDG_DATA_HOME="$S/xdg/data" XDG_RUNTIME_DIR="$S/xdg/runtime" TMPDIR="$S/tmp" \
  LOCALAPPDATA="$S/localappdata" PYTHONPATH="$SRC" PYTHONDONTWRITEBYTECODE=1 \
  timeout 600 "$PY" -P "$S/$1" 2>&1
echo "exit=$?"
