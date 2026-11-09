#!/bin/bash
# E5 mutant-B round-2 driver — run on <runner>. Reads mutants/manifest.txt.
set -u
ROOT=/tmp/b103-e5-4-mutr2B
BASE=$ROOT/base
PY=/home/<user>/miniconda3/envs/s19ci/bin/python
export HOME=$ROOT/<user>
export XDG_CONFIG_HOME=$ROOT/<user>/.config
export XDG_CACHE_HOME=$ROOT/<user>/.cache
export XDG_DATA_HOME=$ROOT/<user>/.local/share
export LOCALAPPDATA=$ROOT/<user>/.localappdata
export PYTHONDONTWRITEBYTECODE=1
mkdir -p $ROOT/out

run_one() {
  local mid=$1 kind=$2 mod=$3 k=$4
  echo "=== $mid ($kind) ==="
  rm -rf $ROOT/$mid
  cp -a $BASE $ROOT/$mid
  cp $ROOT/mutants/$mid.py $ROOT/$mid/s19_app/tui/services/label_match.py
  {
    echo "===== diff -u (base vs mutant) s19_app/tui/services/label_match.py ====="
    diff -u $BASE/s19_app/tui/services/label_match.py $ROOT/$mid/s19_app/tui/services/label_match.py || true
    echo "===== pytest tail ====="
    if [ "$kind" = "p" ]; then
      echo "--- uptime before ---"
      uptime
      ( cd $ROOT/$mid && $PY -m pytest -q -p no:cacheprovider "$mod" -k "$k" 2>&1 | tail -80 )
      echo "--- uptime after ---"
      uptime
    else
      ( cd $ROOT/$mid && $PY -m pytest -q -p no:cacheprovider "$mod" -k "$k" 2>&1 | tail -80 )
    fi
  } > $ROOT/out/$mid.txt 2>&1
  rm -rf $ROOT/$mid
  echo "done $mid -> $(grep -E '[0-9]+ (passed|failed)' $ROOT/out/$mid.txt | tail -1)"
}

# behaviour first, then perf
while IFS=$'\t' read -r mid kind mod k; do
  [ -z "$mid" ] && continue
  [ "$kind" = "b" ] && run_one "$mid" "$kind" "$mod" "$k"
done < $ROOT/mutants/manifest.txt

while IFS=$'\t' read -r mid kind mod k; do
  [ -z "$mid" ] && continue
  [ "$kind" = "p" ] && run_one "$mid" "$kind" "$mod" "$k"
done < $ROOT/mutants/manifest.txt

echo ALLDONE
