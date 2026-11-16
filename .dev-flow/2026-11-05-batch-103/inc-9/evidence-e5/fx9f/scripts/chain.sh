#!/bin/bash
# FX9f chain: A the four timing nodes alone (-n 0), each after a 1-min load < 2; B stall controls (same rule).
S=~/work/zq-fx9f; cd $S; L=out/chain-log.txt; echo "start $(date)" > $L
J=tests/test_b103_inc9_w_jobs.py
sumline() { grep -E '(passed|failed|error)( in|,)' out/$1 | tail -1; }
node() { # <label> <tree> <out> <test id prefix>
  l=$(./waitload.sh) || { echo "$1: not measured (load $l)" >> $L; return; }
  TMO=900 ./run.sh $S/$2 $3 -n 0 -m serial_timing -k "$4" $J
  echo "$1 (load before $l): $(sumline $3) | $(grep -oE 'slowest press [0-9.]+ s|right [0-9.]+ s, left [0-9.]+ s|[0-9.]+ s \([0-9.-]+ % margin\)' out/$3 | tr '\n' ' ')" >> $L
}
for n in 29_1 29_2 82_1 20_1; do node "A $n" head t-$n.txt "test_r_pe_bench_${n}_"; done
for t in mp08 mp13; do for n in 29_2 82_1; do node "B $t $n" $t t-$t-$n.txt "test_r_pe_bench_${n}_"; done; done
node "B ma13 29_2" ma13 t-ma13-29_2.txt "test_r_pe_bench_29_2_"
echo "end $(date)" >> $L; echo CHAIN_DONE >> $L
