#!/usr/bin/env bash
# Inc 11 E2 runner (batch-103) for the LAN host <runner>: runs one evidence script against the read-only clone
# ~/work/s19_app (e07fb00) with HOME/XDG/LOCALAPPDATA isolated under /tmp/b103-e2-11/<user> (basename is not
# `home`), no DISPLAY, closed stdin, a timeout; writes /tmp/b103-e2-11/out/<name>-transcript.txt.
# Copied from Inc 3's i3e2-run.sh; the scratch folder, the HOME basename and the script names differ.
# Usage: bash i11e2-run.sh <script name without .py> [extra args...]
set -u
name="$1"; shift
base=/tmp/b103-e2-11
py="$HOME/miniconda3/envs/s19ci/bin/python"
clone="$HOME/work/s19_app"
iso="$base/<user>"
mkdir -p "$iso/lad" "$base/out"
out="$base/out/$name-transcript.txt"
{
  echo "# $name transcript $(date -Iseconds) host $(hostname)"
  echo "# clone $(git -C "$clone" rev-parse HEAD) status: $(git -C "$clone" status --short | wc -l) changed; python $("$py" --version 2>&1)"
  echo "# HOME/XDG/LOCALAPPDATA under $iso; no DISPLAY; no clipboard; stdin closed; load: $(cut -d' ' -f1-3 /proc/loadavg)"
  env -i PATH=/usr/bin:/bin HOME="$iso" XDG_CONFIG_HOME="$iso/.config" \
      XDG_DATA_HOME="$iso/.local/share" XDG_CACHE_HOME="$iso/.cache" \
      LOCALAPPDATA="$iso/lad" PYTHONDONTWRITEBYTECODE=1 \
      timeout 1800 "$py" -I "$base/scripts/$name.py" "$@" < /dev/null 2>&1
  echo "# exit $? ; clone status after: $(git -C "$clone" status --short | wc -l) changed; load: $(cut -d' ' -f1-3 /proc/loadavg)"
} > "$out"
wc -l "$out"
