#!/bin/bash
# usage: newt2.sh <idsfile> <tree> <out>
S=$HOME/work/zq-mw9
cd $S
export MUT_IDS="$(cat $1)" MUT_N=2 MUT_TO=600
~/miniconda3/envs/s19ci/bin/python -I -B drv/mw9_run.py run clone $2 $3 tests/test_b103_inc9_w_mutants.py
echo DONE > $3.done
