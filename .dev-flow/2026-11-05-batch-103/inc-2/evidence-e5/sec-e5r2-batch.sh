#!/bin/bash
# usage: sec-e5r2-batch.sh <script.py> <mode> [<mode> ...]  -- runs each mode of a probe in turn through sec-e5r2-run.sh,
# one transcript per mode in $S/out/<script stem>-<mode>.txt; the corpus modes (corpus, mutate, census) get the two
# corpus lists (fixtures first, then the public files, each in the shell's glob order).
S=/tmp/b103-e5r2-2a-sec
script=$1; shift
stem=$(basename "$script" .py)
for m in "$@"; do
  out="$S/out/${stem}-${m}.txt"
  case "$m" in
    corpus|mutate) args=("$S/tree" "$S" "$m" "$S/fixtures.lst" "$S/files.lst") ;;
    census) args=("$S/tree" "$S/fixtures.lst" "$S/files.lst") ;;
    *) args=("$S/tree" "$S" "$m") ;;
  esac
  start=$(date +%s)
  timeout 7200 bash "$S/sec-e5r2-run.sh" "$S/$script" "${args[@]}" > "$out" 2>&1
  echo "exit=$? seconds=$(( $(date +%s) - start ))" >> "$out"
done
