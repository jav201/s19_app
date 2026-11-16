#!/bin/bash
# X10 batch 5: the Inc 10 retarget sites of the b100 files, one by one (tree then base), -rA to name each result.
cd ~/work/zq-x10 || exit 2
for t in exact base; do
  ./run.sh $t "$t-b100-save-sites" -p no:xdist -q -rA tests/test_b100_save_image.py -k "tc_b100_14 or tc_b100_15 or tc_b100_58 or tc_b100_69"
  ./run.sh $t "$t-b100-53a" -p no:xdist -q -rA "tests/test_b100_workers.py::test_tc_b100_53_session_writers_are_refused_during_a_save"
  ./run.sh $t "$t-b100-53b" -p no:xdist -q -rA "tests/test_b100_workers.py::test_tc_b100_53_patch_editor_changes_are_refused_while_busy"
done
echo BATCH5_DONE > logs/BATCH5_DONE
