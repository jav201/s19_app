#!/bin/bash
# FX9 step 3: fresh clone of b103-inc9 (bundle), one run per file (-n 2, timeout 300): every Inc 9 test file
# without the serial_timing / slow nodes (those were decided alone in step 2), the Inc 8 files, then the laws.
S=~/work/zq-fx9
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME:?the HT-02 HOME basename, set by the caller}"
L=$S/out/chain4.log
cd $S/clone || exit 9
echo "clone $(git log --oneline -1 | cut -c1-8) start $(date +%T) load $(cat /proc/loadavg)" >> $L
for f in tests/test_b103_inc9_*.py; do
  b=$(basename $f .py)
  $S/run.sh clone "c-$b.txt" 2 300 -- -q -m "not serial_timing and not slow" $f
  echo "$b $(grep -E '^# rc=|passed|failed|error' $S/out/c-$b.txt | tail -2 | tr '\n' ' ')" >> $L
done
for f in tests/test_b103_inc8_*.py; do
  b=$(basename $f .py)
  $S/run.sh clone "c-$b.txt" 2 300 -- -q $f
  echo "$b $(grep -E '^# rc=|passed|failed|error' $S/out/c-$b.txt | tail -2 | tr '\n' ' ')" >> $L
done
for f in tests/test_id_registry.py tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_address_census.py tests/test_deps_seam_law.py tests/test_no_private_tokens.py tests/test_engine_unchanged.py; do
  b=$(basename $f .py)
  $S/run.sh clone "c-$b.txt" 2 300 -- -q $f
  echo "$b $(grep -E '^# rc=|passed|failed|error' $S/out/c-$b.txt | tail -2 | tr '\n' ' ')" >> $L
done
echo "CHAIN4_DONE $(date +%T) load $(cat /proc/loadavg)" >> $L
