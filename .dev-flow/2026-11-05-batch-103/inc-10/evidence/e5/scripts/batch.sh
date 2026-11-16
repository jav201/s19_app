#!/bin/bash
# Inc 10 E5 (X10) re-run batch on the exact tree and the exact clone; one file group per run, -n 2, timeout 300.
# RUNNER_HOME_NAME is exported by the caller (HT-11).
cd ~/work/zq-x10 || exit 2
R=./run.sh
$R exact i10-g1 -n 2 tests/test_b103_inc10_g1_controls.py tests/test_b103_inc10_g1_panel.py
$R exact i10-g2 -n 2 tests/test_b103_inc10_g2_arms.py tests/test_b103_inc10_g2_write.py
$R exact i10-g3 -n 2 tests/test_b103_inc10_g3_engine.py tests/test_b103_inc10_mu_survivors.py tests/test_b103_inc10_s0_written_name.py
$R exact sh-b97 -n 2 tests/test_b97_patch_editor.py
$R exact sh-v2-layout -n 2 tests/test_tui_patch_editor_v2.py tests/test_tui_patch_layout.py
$R exact sh-b100-tc -n 2 tests/test_b100_active_variant.py -k tc_b100
$R exact sh-b100-rest -n 2 tests/test_b100_active_variant.py -k "not tc_b100"
$R exact sh-b100-other -n 2 tests/test_b100_load_question.py tests/test_b100_save_image.py tests/test_b100_workers.py
$R exact sh-b99-apply -n 2 tests/test_b99_editor_image.py tests/test_b99_s0.py tests/test_changes_apply.py
$R exact sh-inc8-layout-chips -n 2 tests/test_b103_inc8_p_layout.py tests/test_tui_patch_chips.py
$R clone laws -n 2 tests/test_docs_canon.py tests/test_b101_doc_hygiene.py tests/test_b101_help_legend_docs.py tests/test_no_private_tokens.py tests/test_filename_markup_safety.py tests/test_report_markup_safety.py tests/test_id_registry.py tests/test_deps_seam_law.py tests/test_engine_unchanged.py tests/test_requirements_canon.py tests/test_suite_hygiene.py
$R clone laws-tc031 -n 2 tests/test_tui_directionb.py -k tc031
echo BATCH_DONE > logs/BATCH_DONE
