#!/bin/bash
S=$HOME/work/zq-mw9
cd $S
NODE=tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_26_2_a_deselected_large_row_keeps_none_of_its_values
for id in t26b t26; do
  MUT_IDS=$id MUT_N=0 MUT_TO=1800 ~/miniconda3/envs/s19ci/bin/python -I -B drv/mw9_run.py run clone mt out/m262b $NODE
done
echo CHAIN-DONE > out/chain262b.done
