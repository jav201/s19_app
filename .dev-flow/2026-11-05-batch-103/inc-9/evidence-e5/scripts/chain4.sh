#!/bin/bash
# X9 chain 4: after chain 3, the probe on a copy of head (probe file never in head: the hygiene law counts test files).
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
cd ~/work/zq-x9
while [ ! -f out/chain3.done ]; do sleep 10; done
rm -rf probe && cp -r head probe && rm -rf probe/.git && cp test_x9_probe.py probe/tests/
for i in $(seq 1 40); do l=$(cut -d' ' -f1 /proc/loadavg); awk "BEGIN{exit !($l < 2)}" && break; sleep 15; done
TMO=600 ./run.sh ~/work/zq-x9/probe x4-probe.txt -n 0 -s tests/test_x9_probe.py
echo CHAIN4_DONE > out/chain4.done
