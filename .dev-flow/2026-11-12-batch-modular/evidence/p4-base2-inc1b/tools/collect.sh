#!/usr/bin/env bash
# Collect redacted evidence into $S/evid (home path -> ~, host name -> <host>).
set -u
S=$HOME/work/zq-base2
cd "$S" || exit 3
rm -rf evid; mkdir -p evid
H=$(hostname)
red() { sed -e "s#$HOME#~#g" -e "s#$H#<host>#g"; }
PY=$HOME/miniconda3/envs/s19ci/bin/python
for o in "$@"; do
  [ -f "$o/run.txt" ] && red < "$o/run.txt" > "evid/${o#out-}.txt"
done
if [ -f out-a-tip/junit.xml ] && [ -f out-a-merged/junit.xml ]; then
  "$PY" -I junit_cmp.py out-a-tip/junit.xml out-a-merged/junit.xml | red > evid/a-tip-vs-merged.txt
fi
ls evid
