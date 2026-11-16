#!/bin/bash
# X10 batch 4: TC-B100-59 again (load sensitivity check, HT-07/HT-08): the two nodes alone on the tree, then the -k set on tree and base once more.
cd ~/work/zq-x10 || exit 2
./run.sh exact exact-b100-59-two -p no:xdist -q -rfE "tests/test_b100_save_image.py::test_tc_b100_59_open_project_unchanged" "tests/test_b100_save_image.py::test_tc_b100_59_pending_patch_in_the_open_project"
./run.sh exact exact-b100-59-r2 -p no:xdist -q -rfE tests/test_b100_save_image.py -k tc_b100_59
./run.sh base base-b100-59-r2 -p no:xdist -q -rfE tests/test_b100_save_image.py -k tc_b100_59
echo BATCH4_DONE > logs/BATCH4_DONE
