#!/bin/bash
# FX9 chain 3: after chain 2 (timing stays alone on the host), 26_2 on the fixed tree (load < 2 before it),
# then the Inc 9 widget files on it (-n 2, not serial_timing, not slow).
S=~/work/zq-fx9
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME:?the HT-02 HOME basename, set by the caller}"
L=$S/out/chain3.log
N=tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_26_2_a_deselected_large_row_keeps_none_of_its_values
until grep -q CHAIN2_DONE $S/out/chain2.log; do sleep 20; done
waitq() { while :; do l=$(cut -d' ' -f1 /proc/loadavg); awk -v l="$l" 'BEGIN{exit !(l<2)}' && break; echo "wait load $l $(date +%T)" >> $L; sleep 30; done; }
waitq; echo "26_2 fix1 start $(date +%T) load $(cat /proc/loadavg)" >> $L
$S/run.sh fix1 r262-fix.txt 0 900 -- -q $N
echo "26_2 fix1 end $(date +%T) load $(cat /proc/loadavg)" >> $L
$S/run.sh fix2 r-widget.txt 2 900 -- -q -m "not serial_timing and not slow" tests/test_b103_inc9_a9.py tests/test_b103_inc9_i.py tests/test_b103_inc9_w_keys.py tests/test_b103_inc9_w_select.py tests/test_b103_inc9_w_stage.py tests/test_b103_inc9_w_jobs.py tests/test_b103_inc9_w_mutants.py
echo "CHAIN3_DONE $(date +%T)" >> $L
