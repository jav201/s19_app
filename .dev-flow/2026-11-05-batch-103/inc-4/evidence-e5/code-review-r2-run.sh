#!/bin/bash
# batch-103 Inc 4 E5 code review round 2 runner (cachyos-rtx). THROWAWAY EVIDENCE.
# usage: code-review-r2-run.sh setup
#        code-review-r2-run.sh probe <all|det> <hashseed>
# Scratch /tmp/b103-e5r2-4-code: tree = cp -a of the read-only ~/work/b103-int4 (never edited).
S=/tmp/b103-e5r2-4-code
cd "$S" || exit 1
PY="$HOME/miniconda3/envs/s19ci/bin/python"
if [ "$1" = setup ]; then
  [ -d "$S/tree" ] || cp -a "$HOME/work/b103-int4" "$S/tree"
  sha256sum "$S/tree/s19_app/tui/services/label_match.py" "$HOME/work/b103-int4/s19_app/tui/services/label_match.py"
  exit 0
fi
U=$S/zq_iso_user
mkdir -p "$U/.config" "$U/.local/share" "$U/.local/state" "$U/.cache" "$U/localappdata"
export HOME=$U XDG_CONFIG_HOME=$U/.config XDG_DATA_HOME=$U/.local/share XDG_STATE_HOME=$U/.local/state XDG_CACHE_HOME=$U/.cache LOCALAPPDATA=$U/localappdata
export PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=$S/tree PYTHONHASHSEED=$3
unset DISPLAY WAYLAND_DISPLAY CI NO_COLOR
out=code-review-r2-$2-$3-transcript.txt
{
  echo "# E5 code review round 2 probe transcript (inc-4 label_match) - generated, not typed"
  echo "# runner code-review-r2-run.sh sha256 $(sha256sum "$S/code-review-r2-run.sh" | cut -c1-64); probe code-review-r2-probe.py sha256 $(sha256sum "$S/code-review-r2-probe.py" | cut -c1-64)"
  echo "# host $(hostname); HOME=$HOME; load before $(cut -d' ' -f1-3 /proc/loadavg); nproc $(nproc)"
  cd "$S/tree" && timeout 5400 "$PY" -s -u "$S/code-review-r2-probe.py" "$2"
  echo "# probe exit $?; load after $(cut -d' ' -f1-3 /proc/loadavg)"
} > "$S/$out" 2>&1 < /dev/null
echo "done -> $out"
