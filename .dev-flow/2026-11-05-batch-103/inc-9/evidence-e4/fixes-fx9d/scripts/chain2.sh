#!/bin/bash
# FX9d chain 2: fresh clone of b103-inc9 (bundle); one run per file (-n 2, timeout 300): Inc 9 files without serial_timing/slow, Inc 8 files, files that touch the JSON view, laws (HT-03).
S=~/work/zq-fx9d
cd $S && rm -rf clone && git clone -q -b b103-inc9 fx9d.bundle clone || exit 9
L=$S/out/chain2-log.txt
echo "clone $(cd clone && git log --oneline -1 | cut -c1-8) start $(date +%T) load $(cat /proc/loadavg)" > $L
for f in clone/tests/test_b103_inc9_*.py; do
  b=$(basename $f .py)
  ./run.sh $S/clone c-$b.txt -q -n 2 -m "not serial_timing and not slow" tests/$b.py
  echo "$b $(grep -E 'passed|failed|error' out/c-$b.txt | tail -1)" >> $L
done
for f in clone/tests/test_b103_inc8_*.py; do
  b=$(basename $f .py)
  ./run.sh $S/clone c-$b.txt -q -n 2 tests/$b.py
  echo "$b $(grep -E 'passed|failed|error' out/c-$b.txt | tail -1)" >> $L
done
for b in $(cat users.txt); do
  [ -f clone/tests/$b.py ] || { echo "$b MISSING" >> $L; continue; }
  TMO=900 ./run.sh $S/clone c-$b.txt -q -n 2 tests/$b.py
  echo "$b $(grep -E 'passed|failed|error' out/c-$b.txt | tail -1)" >> $L
done
for b in test_id_registry test_suite_hygiene test_requirements_canon test_address_census test_deps_seam_law test_no_private_tokens test_engine_unchanged; do
  [ -f clone/tests/$b.py ] || { echo "$b MISSING" >> $L; continue; }
  ./run.sh $S/clone c-$b.txt -q -n 2 tests/$b.py
  echo "$b $(grep -E 'passed|failed|error' out/c-$b.txt | tail -1)" >> $L
done
echo "CHAIN2_DONE $(date +%T) load $(cat /proc/loadavg)" >> $L
