#!/bin/bash
# X10 batch 2: the three b100 shared files one by one, on the exact tree and on base 439860c4 (comparison).
cd ~/work/zq-x10 || exit 2
for f in test_b100_load_question test_b100_save_image test_b100_workers; do
  ./run.sh exact "sh-$f" -n 2 -q -rfE tests/$f.py
  ./run.sh base "base-$f" -n 2 -q -rfE tests/$f.py
done
echo BATCH2_DONE > logs/BATCH2_DONE
