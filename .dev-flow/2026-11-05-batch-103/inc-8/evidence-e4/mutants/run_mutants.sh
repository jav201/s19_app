#!/bin/bash
# run_mutants.sh <root> <worker> <keyfile>: apply each mutation to the worker's copy, run its mapped nodes, restore
ROOT=$1; W=$2; KEYS=$3
. "$ROOT/mut/run_env.sh"
TREE=$ROOT/$W/tree; PRIS=$ROOT/pristine; S=$ROOT/run/$W
TOUCHED=$(cat "$ROOT/mut/touched.txt")
LOG=$ROOT/res/$W.log; : > "$LOG"
while read -r key; do
  id=${key%%#*}; safe=${key//#/_}; res=$ROOT/res/$safe.txt
  wait_quiet "$LOG"
  { echo "KEY $key"; echo "LOAD_BEFORE $(loadnow)"; uptime; } > "$res"
  "$PY" -I -B "$ROOT/mut/apply_mutant.py" "$TREE" "$key" >> "$res" 2>&1 || { echo "VERDICT $key apply-failed" >> "$res"; echo "$key apply-failed" >> "$LOG"; continue; }
  verdict=survived
  for kind in unit at; do
    nodes=$("$PY" -I -B "$ROOT/mut/nodes_for.py" "$ROOT/mut/nodes.json" "$id" $kind)
    [ -z "$nodes" ] && continue
    echo "RUN $kind nodes=$(echo "$nodes" | wc -l)" >> "$res"
    run_pytest "$TREE" "$S" $nodes > "$res.run" 2>&1; rc=$?
    echo "RC $kind $rc" >> "$res"
    grep -E "^(/|[a-z_/.0-9]+\.py:[0-9]+:)|^(FAILED|ERROR)|passed|failed|error" "$res.run" | tail -8 >> "$res"
    if [ $rc -eq 1 ] || { [ $rc -eq 2 ] && grep -q "^FAILED" "$res.run"; }; then verdict=killed-$kind; break
    elif [ $rc -ne 0 ]; then verdict=inconclusive-rc$rc-$kind; break; fi
  done
  rm -f "$res.run"
  echo "LOAD_AFTER $(loadnow)" >> "$res"
  for f in $TOUCHED; do cp "$PRIS/$f" "$TREE/$f"; done
  if (cd "$TREE" && sha256sum -c "$ROOT/mut/touched.sha" > /dev/null 2>&1); then echo "RESTORE_OK" >> "$res"; else echo "RESTORE_MISMATCH" >> "$res"; echo "$key RESTORE_MISMATCH, worker stopped" >> "$LOG"; echo "VERDICT $key $verdict" >> "$res"; exit 9; fi
  echo "VERDICT $key $verdict" >> "$res"
  echo "$key $verdict" >> "$LOG"
done < "$KEYS"
echo WORKER_DONE >> "$LOG"
