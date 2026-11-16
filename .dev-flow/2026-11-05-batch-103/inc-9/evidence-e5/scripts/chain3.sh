#!/bin/bash
# X9 chain 3: the repaired 29_2 / 82_1 instrument (keys_until from a thread) on head, the arrival mutant and FX9's
# stall mutant (copies only, HT-09); each node alone at -n 0, only when the 1-min load is < 2 (HT-08).
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
cd ~/work/zq-x9
cp w_jobs_x9.py head/tests/test_b103_inc9_w_jobs.py
cp w_jobs_x9.py marr/tests/test_b103_inc9_w_jobs.py
rm -rf mstall && cp -r head mstall && rm -rf mstall/.git && (cd mstall && patch -p1 < ../mutant-stall.diff)
diff -r head/s19_app mstall/s19_app > out/x3-mstall-diff.txt
J=tests/test_b103_inc9_w_jobs.py
L=out/chain3-log.txt; echo "start $(date)" > $L
for spec in "head 29_2" "marr 29_2" "mstall 29_2" "head 82_1" "mstall 82_1"; do
  set -- $spec
  for i in $(seq 1 40); do l=$(cut -d' ' -f1 /proc/loadavg); awk "BEGIN{exit !($l < 2)}" && break; sleep 15; done
  TMO=600 ./run.sh ~/work/zq-x9/$1 x3-$1-$2.txt -n 0 -m serial_timing -k "test_r_pe_bench_${2}_" $J
  echo "$1 $2 (load before $l): $(grep -E '(passed|failed|error)' out/x3-$1-$2.txt | tail -1) $(grep -o 'slowest press [0-9.]* s\|reached the sheet[^\"]*' out/x3-$1-$2.txt | head -1)" >> $L
done
echo "end $(date)" >> $L; echo CHAIN3_DONE > out/chain3.done
