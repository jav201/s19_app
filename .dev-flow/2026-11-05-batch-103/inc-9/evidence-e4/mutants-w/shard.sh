#!/bin/bash
# usage: shard.sh <k> <tree>
S=$HOME/work/zq-mw9
cd $S
export MUT_IDS="$(cat drv/shard$1.ids)" MUT_N=2 MUT_TO=900 MUT_MARK="not serial_timing and not slow"
~/miniconda3/envs/s19ci/bin/python -I -B drv/mw9_run.py run clone $2 out/sh$1 tests/test_b103_inc9_a9.py tests/test_b103_inc9_i.py tests/test_b103_inc9_w_keys.py tests/test_b103_inc9_w_select.py tests/test_b103_inc9_w_stage.py tests/test_b103_inc9_w_jobs.py
echo DONE > out/sh$1.done
