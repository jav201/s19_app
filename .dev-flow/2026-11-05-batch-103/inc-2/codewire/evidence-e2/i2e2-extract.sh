#!/usr/bin/env bash
# Inc 2 E2: run i2e2-extract.py on the LAN host over a FRESH throwaway copy of the base tree
# (git archive e07fb00 s19_app tools/synth from the read-only clone; the clone is not written).
# The Code-Wire tools are a copy of the local clone at v3.1.0 (e436a08) under /tmp/b103-e2-2/cw.
# Usage: bash i2e2-extract.sh census | check <graph.md>
set -u
mode="$1"; shift
base=/tmp/b103-e2-2
py="$HOME/miniconda3/envs/s19ci/bin/python"
clone="$HOME/work/s19_app"
copy="$base/copy-$mode"
rm -rf "$copy" "$base/out/cw-$mode"
mkdir -p "$copy" "$base/out"
git -C "$clone" archive e07fb00 s19_app tools/synth | tar -x -C "$copy"
out="$base/out/i2e2-extract-$mode-transcript.txt"
{
  echo "# i2e2-extract $mode transcript $(date -Iseconds) host $(hostname)"
  echo "# copy: git archive e07fb00 s19_app tools/synth -> $copy (clone $(git -C "$clone" rev-parse HEAD), status $(git -C "$clone" status --short | wc -l) changed)"
  echo "# code-wire: $(cat "$base/cw/VERSION.txt"); python $("$py" --version 2>&1)"
  timeout 900 "$py" -I "$base/scripts/i2e2-extract.py" "$mode" "$copy" "$base/cw" "$base/out" "$@" < /dev/null 2>&1
  echo "# exit $?"
} > "$out"
wc -l "$out"
