#!/usr/bin/env bash
# Re-run each B2 swap alone, serially, on base (a95d0ea9) and after (66544e8e); record the host load.
set -u
S=$HOME/work/zq-base2
OUT=$S/rerun.tsv; : > "$OUT"
while IFS= read -r node; do
  [ -z "$node" ] && continue
  for side in base after; do
    T="$S/base"; [ "$side" = after ] && T="$S/after/tree"
    L=$(cut -d' ' -f1-3 /proc/loadavg)
    bash "$S/run_t.sh" "$T" "$S/out-rr" 0 900 "$node"
    R=$(grep -E '[0-9]+ (passed|failed)' "$S/out-rr/run.txt" | tail -1)
    printf '%s\tload=%s\t%s\trc=%s\t%s\n' "$side" "$L" "$node" "$(cat "$S/out-rr/rc")" "$R" >> "$OUT"
  done
done < "$S/swaps.txt"
echo RERUN_DONE >> "$OUT"
