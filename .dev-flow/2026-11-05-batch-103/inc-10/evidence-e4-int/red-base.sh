#!/bin/bash
R=$HOME/work/zq-e4-10-int/run.sh
for f in g1_panel g1_controls g2_arms g2_write g3_engine s0_written_name; do
  $R base red-base-$f -n 2 -q -rf tests/test_b103_inc10_$f.py > /dev/null
done
$R base red-base-shared -n 2 -q -rf tests/test_b97_patch_editor.py tests/test_tui_patch_layout.py tests/test_tui_patch_editor_v2.py tests/test_b100_active_variant.py tests/test_b99_editor_image.py > /dev/null
echo done > $HOME/work/zq-e4-10-int/logs/red-base.done
