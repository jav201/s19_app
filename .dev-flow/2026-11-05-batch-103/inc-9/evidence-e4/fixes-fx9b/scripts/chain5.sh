#!/bin/bash
# FX9b step 3: fresh clone of b103-inc9 (bundle), one run per file (-n 2, timeout 300): every Inc 9 test file without
# the serial_timing / slow nodes (decided alone in chain 4), the Inc 8 files, then the laws (HT-03).
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
S=~/work/zq-fx9b
cd $S && rm -rf clone && git clone -q -b b103-inc9 fx9b.bundle clone || exit 9
L=$S/out/chain5-log.txt
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
for b in test_id_registry test_suite_hygiene test_requirements_canon test_address_census test_deps_seam_law test_no_private_tokens test_engine_unchanged; do
  ./run.sh $S/clone c-$b.txt -q -n 2 tests/$b.py
  echo "$b $(grep -E 'passed|failed|error' out/c-$b.txt | tail -1)" >> $L
done
echo "CHAIN5_DONE $(date +%T) load $(cat /proc/loadavg)" >> $L
