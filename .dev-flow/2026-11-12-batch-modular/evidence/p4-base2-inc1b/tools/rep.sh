#!/usr/bin/env bash
# N alone runs of one node on base and after, interleaved; records rc, load and the failure line.
set -u
S=$HOME/work/zq-base2
N="$1"; K="${2:-10}"
OUT=$S/rep.tsv; : > "$OUT"
for i in $(seq 1 "$K"); do
  for side in base after; do
    T="$S/base"; [ "$side" = after ] && T="$S/after/tree"
    L=$(cut -d' ' -f1-3 /proc/loadavg)
    bash "$S/run_t.sh" "$T" "$S/out-rep" 0 300 "$N"
    E=$(grep -E '^E ' "$S/out-rep/run.txt" | head -2 | tr '\n' ' ' | cut -c1-200)
    M=$(grep -E 'cap painted|cap load' "$S/out-rep/run.txt" | sed -E 's/ +TC-B100-61 / /; s/ tests\/.*//' | tr '\n' ';')
    printf '%s\t%s\tload=%s\trc=%s\t%s\t%s\n' "$i" "$side" "$L" "$(cat "$S/out-rep/rc")" "$M" "$E" >> "$OUT"
  done
done
echo REP_DONE >> "$OUT"
