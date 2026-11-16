#!/bin/bash
# X10 batch 3: the save_image TC-B100-59 nodes and the workers TC-B100-53 nodes (the Inc 10 retarget sites), one worker, tree then base.
cd ~/work/zq-x10 || exit 2
for t in exact base; do
  ./run.sh $t "$t-b100-59" -p no:xdist -q -rfE tests/test_b100_save_image.py -k tc_b100_59
  ./run.sh $t "$t-b100-53" -p no:xdist -q -rfE tests/test_b100_workers.py -k tc_b100_53
done
echo BATCH3_DONE > logs/BATCH3_DONE
