#!/bin/bash
# X9 chain 1: arrival mutant on 29_2, then 82_1-style check not needed; one node at a time, -n 0.
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
cd ~/work/zq-x9
N=tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_29_2_a_cursor_key_while_the_preview_result_arrives_is_handled_within_half_a_second
TMO=400 ./run.sh ~/work/zq-x9/marr m292-arrival.txt -n 0 "$N"
echo CHAIN1_DONE > out/chain1.done
