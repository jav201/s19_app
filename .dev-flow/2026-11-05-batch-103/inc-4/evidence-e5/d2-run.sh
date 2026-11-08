#!/bin/bash
# batch-103 Inc 4 E5 design-gap pass round 2 (E5S-07/-08/-09) probe runner (<runner>).
# usage: d2-run.sh <mode> [N]     modes: curve | verify N | build | census | beyond N
# Scratch: /tmp/b103-e5d2-4 (tree = cp -a of the read-only ~/work/b103-int4; pilot = the E3 pilot copy, for the round-1 oracle).
S=/tmp/b103-e5d2-4
cd "$S" || exit 1
PY="$HOME/miniconda3/envs/s19ci/bin/python"
CORPUS_DIR="$HOME/a2l-corpus"
U=$S/<user>
mkdir -p "$U/.config" "$U/.local/share" "$U/.local/state" "$U/.cache" "$U/localappdata"
export HOME=$U XDG_CONFIG_HOME=$U/.config XDG_DATA_HOME=$U/.local/share XDG_STATE_HOME=$U/.local/state XDG_CACHE_HOME=$U/.cache LOCALAPPDATA=$U/localappdata
export PYTHONDONTWRITEBYTECODE=1 TREE=$S/tree PILOT_DIR=$S/pilot CORPUS=$CORPUS_DIR AS_CAP_GIB=8
unset DISPLAY WAYLAND_DISPLAY
out=d2-$1${2:+-$2}-transcript.txt
{
  echo "runner d2-run.sh sha256 $(sha256sum "$S/d2-run.sh" | cut -c1-64); probe d2-probe.py sha256 $(sha256sum "$S/d2-probe.py" | cut -c1-64); sec-r2-probe.py $(sha256sum "$S/sec-r2-probe.py" | cut -c1-64); sec-e5-probe.py $(sha256sum "$S/sec-e5-probe.py" | cut -c1-64)"
  timeout 5400 "$PY" -I -B "$S/d2-probe.py" "$@"
  echo "probe exit $?"
} > "$out" 2>&1 < /dev/null
echo "done -> $out"
