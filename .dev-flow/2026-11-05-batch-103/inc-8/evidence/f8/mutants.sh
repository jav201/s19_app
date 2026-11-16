#!/bin/bash
# Negative controls on copies of the tip tree (HT-09). Writes mut-<n>.txt.
cd ~/work/zq-f8 || exit 9
K='share_no_painted_cell or painted_add'
for m in m1 m2 m3; do rm -rf $m; cp -r tip $m; done
# M1 product: the file row painted 2 rows up, over the Inspector pane.
printf '\n#patch_editor_panel #patch_doc_file_row {\n    offset: 0 -2;\n}\n' >> m1/s19_app/tui/styles.tcss
# M2 product: the Add chip routed to validate_doc.
sed -i 's/"patch_entry_add_button": "add_entry"/"patch_entry_add_button": "validate_doc"/' m2/s19_app/tui/screens_directionb/patch_editor/actions.py
# M3 test side: F-I10-1's reading (widget.region in place of the painted region).
sed -i 's/app.screen.find_widget(widget).visible_region/app.screen.find_widget(widget).region/' m3/tests/test_b103_inc8_p_layout.py
for m in m1 m2 m3; do
  echo "== $m diff"; diff -r tip/s19_app $m/s19_app; diff tip/tests/test_b103_inc8_p_layout.py $m/tests/test_b103_inc8_p_layout.py
done > mut-diffs.txt
for m in m1 m2 m3; do ./run.sh $m mut-$m.txt -n 2 tests/test_b103_inc8_p_layout.py -k "$K" -v; done
