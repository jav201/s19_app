#!/bin/bash
# X9 chain 2 on the bundle clone `head` (811198b5): Inc 9 files, Inc 8 files, laws, slow non-timing nodes,
# then each timing node alone at -n 0 only when the 1-min load is < 2 (HT-08), else logged "not run (load)".
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
cd ~/work/zq-x9
H=~/work/zq-x9/head
L=out/chain2-log.txt
echo "start $(date) load $(cat /proc/loadavg)" > $L
for f in $(cd $H && ls tests/test_b103_inc9_*.py); do
  b=$(basename $f .py); ./run.sh $H c-$b.txt -n 2 -m "not serial_timing and not slow" $f
  echo "$b: $(grep -E '(passed|failed|error)' out/c-$b.txt | tail -1)" >> $L
done
for f in $(cd $H && ls tests/test_b103_inc8_*.py); do
  b=$(basename $f .py); ./run.sh $H c-$b.txt -n 2 $f
  echo "$b: $(grep -E '(passed|failed|error)' out/c-$b.txt | tail -1)" >> $L
done
./run.sh $H c-laws.txt -n 2 -rf tests/test_id_registry.py tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_address_census.py tests/test_deps_seam_law.py tests/test_no_private_tokens.py tests/test_engine_unchanged.py
echo "laws: $(grep -E '(passed|failed|error)' out/c-laws.txt | tail -1)" >> $L
J=tests/test_b103_inc9_w_jobs.py
TMO=900 ./run.sh $H c-slow.txt -n 2 -m "slow and not serial_timing" -k "not 26_2" tests/test_b103_inc9_b_cells.py $J
echo "slow (not 26_2): $(grep -E '(passed|failed|error)' out/c-slow.txt | tail -1)" >> $L
for n in 20_1 29_1; do
  l=$(cut -d' ' -f1 /proc/loadavg)
  if awk "BEGIN{exit !($l < 2)}"; then
    TMO=600 ./run.sh $H t-$n.txt -n 0 -m serial_timing -k "test_r_pe_bench_${n}_" $J
    echo "timing $n (load before $l): $(grep -E '(passed|failed|error)' out/t-$n.txt | tail -1)" >> $L
  else
    echo "timing $n: not run (load $l >= 2)" >> $L
  fi
done
echo "end $(date) load $(cat /proc/loadavg)" >> $L
echo CHAIN2_DONE > out/chain2.done
