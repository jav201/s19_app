#!/bin/bash
# X9 chain 5: the one-key-at-a-time instrument on head / arrival mutant / stall mutant (29_2), head 82_1, then the 82_1 probe.
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
cd ~/work/zq-x9
for t in head marr mstall; do cp w_jobs_x9.py $t/tests/test_b103_inc9_w_jobs.py; done
rm -rf probe && cp -r head probe && rm -rf probe/.git && cp test_x9_probe82.py probe/tests/
J=tests/test_b103_inc9_w_jobs.py
L=out/chain5-log.txt; echo "start $(date)" > $L
for spec in "head 29_2" "marr 29_2" "mstall 29_2" "head 82_1"; do
  set -- $spec
  for i in $(seq 1 40); do l=$(cut -d' ' -f1 /proc/loadavg); awk "BEGIN{exit !($l < 2)}" && break; sleep 15; done
  TMO=600 ./run.sh ~/work/zq-x9/$1 x5-$1-$2.txt -n 0 -m serial_timing -k "test_r_pe_bench_${2}_" $J
  echo "$1 $2 (load before $l): $(grep -E '(passed|failed|error)' out/x5-$1-$2.txt | tail -1) $(grep -o 'slowest press [0-9.]* s\|reached the sheet[^\"]*' out/x5-$1-$2.txt | head -1)" >> $L
done
for i in $(seq 1 40); do l=$(cut -d' ' -f1 /proc/loadavg); awk "BEGIN{exit !($l < 2)}" && break; sleep 15; done
TMO=600 ./run.sh ~/work/zq-x9/probe x5-probe82.txt -n 0 -s tests/test_x9_probe82.py
echo "probe82 (load before $l): $(grep -E '(passed|failed|error)' out/x5-probe82.txt | tail -1)" >> $L
echo "end $(date)" >> $L; echo CHAIN5_DONE > out/chain5.done
