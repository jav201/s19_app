#!/bin/bash
R=$HOME/work/zq-e4-10-int/run.sh
for f in test_b103_inc10_g1_panel test_b103_inc10_g1_controls test_b103_inc10_g2_arms test_b103_inc10_g2_write test_b103_inc10_g3_engine test_b103_inc10_s0_written_name test_b97_patch_editor test_tui_patch_layout test_tui_patch_editor_v2 test_b99_editor_image test_tui_patch_chips; do
  $R final final-$f -n 2 -q -rf tests/$f.py > /dev/null
done
$R final final-test_b100_active_variant-tc -n 2 -q -rf -k tc_b100 tests/test_b100_active_variant.py > /dev/null
$R final final-test_b100_active_variant-rest -n 2 -q -rf -k "not tc_b100" tests/test_b100_active_variant.py > /dev/null
$R final final-other-saveback -n 2 -q -rf tests/test_b100_save_image.py::test_tc_b100_14_save_back_then_emit tests/test_b100_save_image.py::test_tc_b100_15_save_back_then_save_project_keeps_the_patch tests/test_b100_save_image.py::test_tc_b100_58_save_back_records_the_saved_state tests/test_b100_save_image.py::test_tc_b100_69_sec4_junction_save_back_stages_in_this_work_area tests/test_b100_workers.py::test_tc_b100_53_session_writers_are_refused_during_a_save tests/test_b100_workers.py::test_tc_b100_53_patch_editor_changes_are_refused_while_busy tests/test_b100_load_question.py::test_tc_b100_44_twenty_four_cells_ask_by_kind tests/test_changes_apply.py tests/test_b99_s0.py > /dev/null
$R final final-dock-height -q -s -rf -k dock tests/test_b103_inc10_g1_panel.py > /dev/null
echo done > $HOME/work/zq-e4-10-int/logs/final.done
