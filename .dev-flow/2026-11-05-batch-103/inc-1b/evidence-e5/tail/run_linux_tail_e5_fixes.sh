#!/usr/bin/env bash
set -euo pipefail

repo=<HOME>/Github/s19_app-b103-inc1b-integration
scratch=$(mktemp -d /tmp/b103-tail-e5-fixes.XXXXXX)
trap 'rm -rf "$scratch"' EXIT

cd "$repo"
export HOME="$scratch/home"
export TMPDIR="$scratch/tmp"
export XDG_CACHE_HOME="$scratch/cache"
export XDG_CONFIG_HOME="$scratch/config"
export XDG_DATA_HOME="$scratch/data"
export LOCALAPPDATA="$scratch/local"
mkdir -p "$HOME" "$TMPDIR" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$LOCALAPPDATA"
unset DISPLAY WAYLAND_DISPLAY
export PYTEST_ADDOPTS=

timeout 900s <HOME>/s19venv/bin/python -I -B \
    .dev-flow/2026-11-05-batch-103/inc-1b/evidence-e5/tail/run_linux_tail_e5_fixes.py \
    < /dev/null
