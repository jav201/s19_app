#!/bin/bash
# FX9b chain 4: the timing nodes on the fixed head (4c52ea99), each alone at -n 0 after a 1-min load < 2,
# then X9's arrival mutant and FX9's stall mutant on copies (HT-09).
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
cd ~/work/zq-fx9b
rm -rf head marr mstall && mkdir head && tar -xf head.tar -C head
cp -r head marr && ~/miniconda3/envs/s19ci/bin/python -I mutant-arrival.py marr
cp -r head mstall && (cd mstall && patch -p1 < ../mutant-stall.diff)
diff -r head/s19_app marr/s19_app > out/t-marr-diff.txt; diff -r head/s19_app mstall/s19_app > out/t-mstall-diff.txt
J=tests/test_b103_inc9_w_jobs.py
L=out/chain4-log.txt; echo "start $(date)" > $L
for spec in "head 29_1" "head 29_2" "head 82_1" "head 20_1" "marr 29_2" "mstall 29_2" "mstall 82_1"; do
  set -- $spec
  l=$(./waitload.sh)
  TMO=600 ./run.sh ~/work/zq-fx9b/$1 t-$1-$2.txt -n 0 -m serial_timing -k "test_r_pe_bench_${2}_" $J
  echo "$1 $2 (load before $l): $(grep -E '(passed|failed|error)' out/t-$1-$2.txt | tail -1) | $(grep -oE '(slowest press|right) [0-9.]+ s[^\"]*' out/t-$1-$2.txt | head -1)" >> $L
done
echo "end $(date)" >> $L; echo CHAIN4_DONE >> $L
