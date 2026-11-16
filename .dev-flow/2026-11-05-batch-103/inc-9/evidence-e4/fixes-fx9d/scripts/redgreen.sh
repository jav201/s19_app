#!/bin/bash
# RED on the base-code tree, GREEN on the fix, node 2 RED on a leak mutant (copy of green; HT-09).
S=~/work/zq-fx9d; cd $S
rm -rf mut && cp -r green mut && printf '\nTextArea.find_matching_bracket = lambda self, bracket, search_from: None\n' >> mut/s19_app/tui/screens_directionb/patch_editor/document.py
N=tests/test_b103_inc9_ob_json_view.py
./run.sh $S/red red.txt -n 0 $N
./run.sh $S/green green.txt -n 0 $N
./run.sh $S/mut mut.txt -n 0 $N
echo RG_DONE > out/rg-done.txt
