#!/bin/bash
# FX9c chain 3: the user files that failed in the fresh clone (chain 2), re-run whole on a base clone at 16b00234 with
# the same runner, to tell base-identical failures from new ones; test_b97_width (timed out at 300 s) on both clones
# with a 900 s timeout.
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
S=~/work/zq-fx9c
cd $S && rm -rf baseclone && git clone -q -b b103-inc9 fx9c.bundle baseclone && (cd baseclone && git checkout -q 16b00234) || exit 9
L=$S/out/chain3-log.txt
echo "baseclone $(cd baseclone && git log --oneline -1 | cut -c1-8) start $(date +%T) load $(cat /proc/loadavg)" > $L
for b in test_b100_session_reset test_b103_clipboard_core test_b103_copy_paste_matrix test_b97_chips_help test_b99_editor_image test_tui_patch_card test_tui_patch_editor_b94 test_tui_patch_history_strip test_tui_patch_json test_tui_snapshot; do
  TMO=600 ./run.sh $S/baseclone b-$b.txt -q -n 2 tests/$b.py
  echo "base $b $(grep -E 'passed|failed|error' out/b-$b.txt | tail -1)" >> $L
done
TMO=900 ./run.sh $S/baseclone b-test_b97_width.txt -q -n 2 tests/test_b97_width.py
echo "base test_b97_width $(grep -E 'passed|failed|error' out/b-test_b97_width.txt | tail -1)" >> $L
TMO=900 ./run.sh $S/clone c2-test_b97_width.txt -q -n 2 tests/test_b97_width.py
echo "head test_b97_width $(grep -E 'passed|failed|error' out/c2-test_b97_width.txt | tail -1)" >> $L
echo "CHAIN3_DONE $(date +%T) load $(cat /proc/loadavg)" >> $L
