#!/bin/bash
# FX9b probe chain 1: record-stage profile + arrival split on the base tree.
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
cd ~/work/zq-fx9b
rm -rf probe && cp -r base probe && cp test_fx9b_probe.py probe/tests/
L=out/probe1-log.txt; echo "start $(date)" > $L
for n in record arrival; do
  l=$(./waitload.sh)
  TMO=600 ./run.sh ~/work/zq-fx9b/probe p1-$n.txt -n 0 -s -k "test_probe_$n" tests/test_fx9b_probe.py
  echo "$n (load before $l): $(grep -E '(passed|failed|error)' out/p1-$n.txt | tail -1)" >> $L
done
echo "end $(date)" >> $L; echo PROBE1_DONE >> $L
