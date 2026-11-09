#!/bin/bash
# batch-103 Inc 4 E5 round-3 DESIGN pilot runner (<runner>). THROWAWAY EVIDENCE.
# usage: d3-run.sh setup
#        d3-run.sh probe <keep|cases|det|ascii> [hashseed]
#        d3-run.sh pytest <tag> <budget|off> <ascii 0|1> <test file>   (the test module under the d3 pilot plugin)
# Scratch /tmp/b103-e5d3-4: tree = cp -a of the read-only ~/work/b103-int4; pilot = cp -a of the reviewer's E3 pilot copy.
S=/tmp/b103-e5d3-4
cd "$S" || exit 1
PY="$HOME/miniconda3/envs/s19ci/bin/python"
if [ "$1" = setup ]; then
  [ -d "$S/tree" ] || cp -a "$HOME/work/b103-int4" "$S/tree"
  [ -d "$S/pilot" ] || cp -a /tmp/b103-e5r3-4-sec/pilot "$S/pilot"
  cp sec-r3-probe.py sec-e5-probe.py d3-pilot.py d3-probe.py "$S/" 2>/dev/null
  mkdir -p "$S/plug" && cp d3-plugin.py "$S/plug/d3_plugin.py"
  sha256sum "$S/tree/s19_app/tui/services/label_match.py" ~/work/b103-int4/s19_app/tui/services/label_match.py
  exit 0
fi
U=$S/<user>
mkdir -p "$U/.config" "$U/.local/share" "$U/.local/state" "$U/.cache" "$U/localappdata"
export HOME=$U XDG_CONFIG_HOME=$U/.config XDG_DATA_HOME=$U/.local/share XDG_STATE_HOME=$U/.local/state XDG_CACHE_HOME=$U/.cache LOCALAPPDATA=$U/localappdata
export PYTHONDONTWRITEBYTECODE=1 TREE=$S/tree PILOT_DIR=$S/pilot REPO=$S/tree OUT=$S/out AS_CAP_GIB=8 SCRATCH=$S D3_PILOT=$S/d3-pilot.py
unset DISPLAY WAYLAND_DISPLAY CI NO_COLOR
if [ "$1" = probe ]; then
  export PYTHONPATH=$S/tree
  if [ -n "$3" ]; then export PYTHONHASHSEED=$3; out=d3-$2-$3-transcript.txt; else out=d3-$2-transcript.txt; fi
  {
    echo "runner d3-run.sh sha256 $(sha256sum "$S/d3-run.sh" | cut -c1-64); probe d3-probe.py sha256 $(sha256sum d3-probe.py | cut -c1-64)"
    timeout 5400 "$PY" -s d3-probe.py "$2"
    echo "probe exit $?"
  } > "$out" 2>&1 < /dev/null
else
  export PYTHONPATH=$S/plug:$S/tree D3_BUDGET=$3 D3_ASCII=$4
  out=d3-pytest-$2-transcript.txt
  {
    echo "runner d3-run.sh sha256 $(sha256sum "$S/d3-run.sh" | cut -c1-64); plugin d3_plugin.py sha256 $(sha256sum plug/d3_plugin.py | cut -c1-64); D3_BUDGET=$3 D3_ASCII=$4; load $(cut -d' ' -f1-3 /proc/loadavg)"
    cd "$S/tree" && timeout 3600 "$PY" -s -m pytest "$5" -p d3_plugin -p no:cacheprovider -p no:randomly -q -rf -o addopts="" 2>&1
    echo "pytest exit $?; load $(cut -d' ' -f1-3 /proc/loadavg)"
  } > "$S/$out" 2>&1 < /dev/null
fi
echo "done -> $out"
