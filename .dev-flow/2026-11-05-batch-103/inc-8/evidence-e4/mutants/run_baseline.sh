#!/bin/bash
# run_baseline.sh <root>: every mapped node on the pristine tree, one test file per pytest run
ROOT=$1
. "$ROOT/mut/run_env.sh"
OUT=$ROOT/res/baseline.txt; : > "$OUT"
"$PY" -I -B "$ROOT/mut/nodes_for.py" "$ROOT/mut/nodes.json" --by-file | while IFS=$'\t' read -r file nodes; do
  wait_quiet "$OUT"
  echo "== $file load $(loadnow)" >> "$OUT"
  run_pytest "$ROOT/pristine" "$ROOT/run/base" $nodes >> "$OUT" 2>&1
  echo "BASELINE_RC $file $?" >> "$OUT"
done
echo BASELINE_DONE >> "$OUT"
