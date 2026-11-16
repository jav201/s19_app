#!/bin/bash
# FX9b chain 3: RED/GREEN of the small fixes, then probe 3 (spin / encode / idle phases).
export RUNNER_HOME_NAME_FROM_CALLER
cd ~/work/zq-fx9b
./redgreen.sh
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
cp test_fx9b_probe3.py probe/tests/
l=$(./waitload.sh)
TMO=600 ./run.sh ~/work/zq-fx9b/probe p3-phases.txt -n 0 -s tests/test_fx9b_probe3.py
echo "phases (load before $l): $(grep -E '(passed|failed|error)' out/p3-phases.txt | tail -1)" >> out/redgreen-log.txt
echo CHAIN3_DONE >> out/redgreen-log.txt
