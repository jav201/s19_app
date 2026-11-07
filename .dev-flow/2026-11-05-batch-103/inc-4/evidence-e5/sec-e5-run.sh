#!/bin/bash
# batch-103 Inc 4 E5 security probe runner (cachyos-rtx). usage: sec-e5-run.sh <mode> [hashseed]
# Scratch: /tmp/b103-e5-4-sec (tree = cp -a of the read-only integrated tree; pilot = cp -a of the E3 pilot).
S=/tmp/b103-e5-4-sec
cd "$S" || exit 1
PY="$HOME/miniconda3/envs/s19ci/bin/python"
U=$S/zq_iso_user
mkdir -p "$U/.config" "$U/.local/share" "$U/.local/state" "$U/.cache" "$U/localappdata"
export HOME=$U XDG_CONFIG_HOME=$U/.config XDG_DATA_HOME=$U/.local/share XDG_STATE_HOME=$U/.local/state XDG_CACHE_HOME=$U/.cache LOCALAPPDATA=$U/localappdata
export PYTHONDONTWRITEBYTECODE=1 TREE=$S/tree PYTHONPATH=$S/tree PILOT_DIR=$S/pilot REPO=$S/tree OUT=$S/out AS_CAP_GIB=8
unset DISPLAY WAYLAND_DISPLAY
if [ -n "$2" ]; then export PYTHONHASHSEED=$2; out=sec-e5-$1-$2-transcript.txt; else out=sec-e5-$1-transcript.txt; fi
timeout 3000 "$PY" -s sec-e5-probe.py "$1" > "$out" 2>&1 < /dev/null
echo "exit $? -> $out"
