#!/bin/bash
# FX9b probe chain 2: record-stage parts (wall clock) and the switch-interval what-if.
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
cd ~/work/zq-fx9b
cp test_fx9b_probe.py test_fx9b_probe2.py probe/tests/
L=out/probe2-log.txt; echo "start $(date)" > $L
for spec in "parts 0" "arrival_swi 0" "arrival_swi 0.0005" "parts 0.0005"; do
  set -- $spec
  l=$(./waitload.sh)
  FX9B_SWI=$2 TMO=600 ./run.sh ~/work/zq-fx9b/probe p2-$1-$2.txt -n 0 -s -k "test_probe_$1" tests/test_fx9b_probe2.py
  echo "$1 swi=$2 (load before $l): $(grep -E '(passed|failed|error)' out/p2-$1-$2.txt | tail -1)" >> $L
done
echo "end $(date)" >> $L; echo PROBE2_DONE >> $L
