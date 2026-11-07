#!/bin/bash
# batch-103 Inc 4 E5 security probe runner, ROUND 4 (cachyos-rtx).
# usage: sec-r4-run.sh <r1|r4> <mode> [hashseed]   (r1 = the round-1 probe sec-e5-probe.py, r4 = sec-r4-probe.py)
# Scratch: /tmp/b103-e5r4-4-sec (tree = cp -a of the read-only ~/work/b103-int4; pilot = cp -a of the E3 pilot copy).
S=/tmp/b103-e5r4-4-sec
cd "$S" || exit 1
PY="$HOME/miniconda3/envs/s19ci/bin/python"
U=$S/zq_iso_user
mkdir -p "$U/.config" "$U/.local/share" "$U/.local/state" "$U/.cache" "$U/localappdata"
export HOME=$U XDG_CONFIG_HOME=$U/.config XDG_DATA_HOME=$U/.local/share XDG_STATE_HOME=$U/.local/state XDG_CACHE_HOME=$U/.cache LOCALAPPDATA=$U/localappdata
export PYTHONDONTWRITEBYTECODE=1 TREE=$S/tree PYTHONPATH=$S/tree PILOT_DIR=$S/pilot REPO=$S/tree OUT=$S/out AS_CAP_GIB=8
unset DISPLAY WAYLAND_DISPLAY
if [ "$1" = r1 ]; then probe=sec-e5-probe.py; tag=r1-$2; else probe=sec-r4-probe.py; tag=$2; fi
if [ -n "$3" ]; then export PYTHONHASHSEED=$3; out=sec-r4-$tag-$3-transcript.txt; else out=sec-r4-$tag-transcript.txt; fi
{
  echo "runner sec-r4-run.sh sha256 $(sha256sum "$S/sec-r4-run.sh" | cut -c1-64); probe $probe sha256 $(sha256sum "$probe" | cut -c1-64)"
  timeout 5400 "$PY" -s "$probe" "$2"
  echo "probe exit $?"
} > "$out" 2>&1 < /dev/null
echo "done -> $out"
