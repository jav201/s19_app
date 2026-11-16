#!/bin/bash
# FX9 chain 2 (timing, HT-08): after chain 1, each node alone (-n 0) once the 1-min load is < 2.
#   base  = a8c936ee (old instrument)        : 29_1, 29_2, 82_1   (RED expected on 29_2, 82_1)
#   fix2  = product fix + handled_press      : 29_1, 29_2, 82_1   (GREEN expected)
#   fix2m = fix2 + UI-thread stall mutant    : 29_2, 82_1         (RED expected: the new instrument bites)
S=~/work/zq-fx9
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME:?the HT-02 HOME basename, set by the caller}"
L=$S/out/chain2.log
F=tests/test_b103_inc9_w_jobs.py
N291=$F::test_r_pe_bench_29_1_a_cursor_key_over_a_previewed_large_edit_is_handled_within_half_a_second
N292=$F::test_r_pe_bench_29_2_a_cursor_key_while_the_preview_result_arrives_is_handled_within_half_a_second
N821=$F::test_r_pe_bench_82_1_a_key_is_handled_within_half_a_second_while_a_record_encode_runs
until grep -q CHAIN1_DONE $S/out/chain1.log; do sleep 20; done
waitq() { while :; do l=$(cut -d' ' -f1 /proc/loadavg); awk -v l="$l" 'BEGIN{exit !(l<2)}' && break; echo "wait load $l $(date +%T)" >> $L; sleep 30; done; }
one() { waitq; echo "$1 $2 start $(date +%T) load $(cat /proc/loadavg)" >> $L; $S/run.sh "$1" "t-$1-$2.txt" 0 300 -- -q -m serial_timing "$3"; echo "$1 $2 end $(date +%T) load $(cat /proc/loadavg) $(tail -3 $S/out/t-$1-$2.txt | grep -E 'passed|failed' )" >> $L; }
one base 291 $N291
one base 292 $N292
one base 821 $N821
one fix2 291 $N291
one fix2 292 $N292
one fix2 821 $N821
one fix2m 292 $N292
one fix2m 821 $N821
echo "CHAIN2_DONE $(date +%T)" >> $L
