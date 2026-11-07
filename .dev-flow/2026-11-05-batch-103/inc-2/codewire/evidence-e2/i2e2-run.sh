#!/usr/bin/env bash
# Inc 2 E2 runner (batch-103) for the LAN host cachyos-rtx: runs one evidence script against the
# read-only clone ~/work/s19_app (e07fb00) with HOME/XDG/LOCALAPPDATA isolated under /tmp/b103-e2-2/home,
# no DISPLAY, closed stdin, a timeout; writes the transcript to /tmp/b103-e2-2/out/<name>-transcript.txt.
# Usage: bash i2e2-run.sh <script name without .py> [extra args...]
set -u
name="$1"; shift
base=/tmp/b103-e2-2
py="$HOME/miniconda3/envs/s19ci/bin/python"
clone="$HOME/work/s19_app"
mkdir -p "$base/home/local" "$base/out"
out="$base/out/$name-transcript.txt"
{
  echo "# $name transcript $(date -Iseconds) host $(hostname)"
  echo "# clone $(git -C "$clone" rev-parse HEAD) status: $(git -C "$clone" status --short | wc -l) changed; python $("$py" --version 2>&1)"
  echo "# HOME/XDG/LOCALAPPDATA under $base/home; no DISPLAY; no clipboard; stdin closed"
  env -i PATH=/usr/bin:/bin HOME="$base/home" XDG_CONFIG_HOME="$base/home/.config" \
      XDG_DATA_HOME="$base/home/.local/share" XDG_CACHE_HOME="$base/home/.cache" \
      LOCALAPPDATA="$base/home/local" \
      timeout 900 "$py" -I "$base/scripts/$name.py" "$clone" "$base/out" "$@" < /dev/null 2>&1
  echo "# exit $?"
} > "$out"
wc -l "$out"
