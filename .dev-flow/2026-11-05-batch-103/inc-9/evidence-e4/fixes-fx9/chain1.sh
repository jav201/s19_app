#!/bin/bash
# FX9 chain 1: 26_2 on the base tree (RED expected), then on the fixed tree, then the Inc 9 widget files on the fixed tree.
S=~/work/zq-fx9
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME:?the HT-02 HOME basename, set by the caller}"
N=tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_26_2_a_deselected_large_row_keeps_none_of_its_values
waitq() { while :; do l=$(cut -d' ' -f1 /proc/loadavg); awk -v l="$l" 'BEGIN{exit !(l<2)}' && break; echo "wait load $l $(date +%T)" >> $S/out/chain1.log; sleep 30; done; }
waitq; echo "26_2 base start $(date +%T) load $(cat /proc/loadavg)" >> $S/out/chain1.log
$S/run.sh base r262-base.txt 0 900 -- -q $N
waitq; echo "26_2 fix start $(date +%T) load $(cat /proc/loadavg)" >> $S/out/chain1.log
$S/run.sh fix1 r262-fix.txt 0 900 -- -q $N
echo "widget start $(date +%T) load $(cat /proc/loadavg)" >> $S/out/chain1.log
$S/run.sh fix1 r-widget.txt 2 900 -- -q -m "not serial_timing and not slow" tests/test_b103_inc9_a9.py tests/test_b103_inc9_i.py tests/test_b103_inc9_w_keys.py tests/test_b103_inc9_w_select.py tests/test_b103_inc9_w_stage.py tests/test_b103_inc9_w_jobs.py tests/test_b103_inc9_w_mutants.py
echo "CHAIN1_DONE $(date +%T)" >> $S/out/chain1.log
