#!/bin/bash
# batch-103 Inc 4 E5 correction probe runner (<runner>). usage: VARIANT=A|C corr-e5-run.sh <mode>
S=/tmp/b103-e5-4-corr
cd "$S" || exit 1
PY="$HOME/miniconda3/envs/s19ci/bin/python"
U=$S/<user>
mkdir -p "$U/.config" "$U/.local/share" "$U/.local/state" "$U/.cache" "$U/localappdata" "$S/pilot"
export HOME=$U XDG_CONFIG_HOME=$U/.config XDG_DATA_HOME=$U/.local/share XDG_STATE_HOME=$U/.local/state XDG_CACHE_HOME=$U/.cache LOCALAPPDATA=$U/localappdata
export PYTHONDONTWRITEBYTECODE=1 TREE=$S/tree PYTHONPATH=$S/tree PILOT_DIR=$S/pilot SEC_PROBE=$S/sec-e5-probe.py AS_CAP_GIB=8
unset DISPLAY WAYLAND_DISPLAY
timeout 3000 "$PY" -s corr-e5-posting-probe.py "$1" > "corr-e5-$1-${VARIANT:-A}-transcript.txt" 2>&1 < /dev/null
echo "exit $? -> corr-e5-$1-${VARIANT:-A}-transcript.txt"
