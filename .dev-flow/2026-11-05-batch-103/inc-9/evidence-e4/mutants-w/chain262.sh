#!/bin/bash
S=$HOME/work/zq-mw9
NODE=tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_26_2_a_deselected_large_row_keeps_none_of_its_values
$S/run.sh $S/clone g262b.txt 0 1800 $NODE -v
cd $S
rm -f mt/tests/probe_262_scratch.py
for id in tfix t26 t26b; do
  MUT_IDS=$id MUT_N=0 MUT_TO=1800 ~/miniconda3/envs/s19ci/bin/python -I -B drv/mw9_run.py run clone mt out/m262 $NODE
done
echo CHAIN-DONE > out/chain262.done
