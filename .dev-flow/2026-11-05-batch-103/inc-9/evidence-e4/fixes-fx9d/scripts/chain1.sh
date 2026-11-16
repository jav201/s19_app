#!/bin/bash
# FX9d chain 1: record-stage probe on red (before) and green (after), then the timing nodes serially on green; each waits for a 1-min load < 2.
S=~/work/zq-fx9d; cd $S; L=out/chain1-log.txt; echo "start $(date)" > $L
for t in red green; do
  l=$(./waitload.sh) || { echo "probe $t: not measured (load $l)" >> $L; continue; }
  TMO=600 ./run.sh $S/$t p-$t.txt -n 0 -s tests/test_fx9c_probe.py
  echo "probe $t (load before $l): $(grep -E '(passed|failed|error)' out/p-$t.txt | tail -1)" >> $L
done
J=tests/test_b103_inc9_w_jobs.py
for n in 29_1 29_2 82_1 20_1; do
  l=$(./waitload.sh) || { echo "$n: not measured (load $l)" >> $L; continue; }
  TMO=600 ./run.sh $S/green t-$n.txt -n 0 -m serial_timing -k "test_r_pe_bench_${n}_" $J
  echo "$n (load before $l): $(grep -E '(passed|failed|error)' out/t-$n.txt | tail -1) | $(grep -oE '(slowest press|right) [0-9.]+ s[^"]*' out/t-$n.txt | head -1)" >> $L
done
echo "end $(date)" >> $L; echo CHAIN1_DONE >> $L
