#!/bin/bash
# run_wider.sh <root> <worker> <keyfile>: for each key, apply it and run EVERY Inc 8 test file (not only the mapped nodes)
ROOT=$1; W=$2; KEYS=$3
. "$ROOT/mut/run_env.sh"
TREE=$ROOT/$W/tree; PRIS=$ROOT/pristine; S=$ROOT/run/$W
TOUCHED=$(cat "$ROOT/mut/touched.txt")
LOG=$ROOT/res/wider-$W.log; : > "$LOG"
FILES="s1 s1_detail s2_picker_definitions a1_service a3_help s2_sheet_rows s2_sheet_keys s2_sheet_formula at_help p_layout p_ledger p_wiring a2_app at"
while read -r key; do
  safe=${key//#/_}; res=$ROOT/res/wider-$safe.txt
  wait_quiet "$LOG"
  { echo "KEY $key"; echo "LOAD_BEFORE $(loadnow)"; } > "$res"
  "$PY" -I -B "$ROOT/mut/apply_mutant.py" "$TREE" "$key" >> "$res" 2>&1 || { echo "VERDICT $key apply-failed" >> "$res"; continue; }
  verdict=survived-wider
  for f in $FILES; do
    run_pytest "$TREE" "$S" "tests/test_b103_inc8_$f.py" > "$res.run" 2>&1; rc=$?
    echo "FILE $f RC $rc" >> "$res"
    if [ $rc -ne 0 ]; then
      grep -E "^(/|[a-z_/.0-9]+\.py:[0-9]+:)|^(FAILED|ERROR)|passed|failed|error" "$res.run" | tail -6 >> "$res"
      if [ $rc -eq 1 ] || { [ $rc -eq 2 ] && grep -q "^FAILED" "$res.run"; }; then verdict=killed-wider-by-$f; else verdict=inconclusive-rc$rc-$f; fi
      break
    fi
  done
  rm -f "$res.run"
  echo "LOAD_AFTER $(loadnow)" >> "$res"
  for f in $TOUCHED; do cp "$PRIS/$f" "$TREE/$f"; done
  if (cd "$TREE" && sha256sum -c "$ROOT/mut/touched.sha" > /dev/null 2>&1); then echo "RESTORE_OK" >> "$res"; else echo "RESTORE_MISMATCH" >> "$res"; exit 9; fi
  echo "VERDICT $key $verdict" >> "$res"
  echo "$key $verdict" >> "$LOG"
done < "$KEYS"
echo WORKER_DONE >> "$LOG"
