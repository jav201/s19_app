#!/bin/bash
# X9r chain: A timing (alone, -n 0, each after a 1-min load < 2); B RED / mutant checks; C fresh-clone battery;
# D base comparisons (history strip; card / JSON / other user files vs 16b00234 and the pre-Inc-9 base 6c4fd21f).
S=~/work/zq-x9r; cd $S; L=out/chain-log.txt; mkdir -p out; echo "start $(date)" > $L
PY=~/miniconda3/envs/s19ci/bin/python
sumline() { grep -E '^(=+ )?[0-9]+ (passed|failed|error|skipped|deselected)|(passed|failed|error)( in|,)' out/$1 | tail -1; }
J=tests/test_b103_inc9_w_jobs.py
for n in 29_1 29_2 82_1 20_1; do
  l=$(./waitload.sh) || { echo "A $n: not measured (load $l)" >> $L; continue; }
  TMO=600 ./run.sh $S/head t-$n.txt -n 0 -m serial_timing -k "test_r_pe_bench_${n}_" $J
  echo "A $n (load before $l): $(sumline t-$n.txt) | $(grep -oE '(slowest press|right|press) [0-9.]+ s' out/t-$n.txt | head -1) | $(grep -oE '[0-9.]+ s \([0-9.]+ % margin\)' out/t-$n.txt | head -1)" >> $L
done
echo "B start $(date)" >> $L
./run.sh $S/c4c891ea9 b-fx9b-red.txt -n 2 -rfE \
  "tests/test_b103_inc9_w_select.py::test_r_pe_bench_11_a_strip_of_more_columns_than_its_room_keeps_the_count_visible" \
  "tests/test_b103_inc9_b_detail.py::test_r_pe_bench_50_the_2d_array_name_keeps_its_where_whole" \
  "tests/test_b103_inc9_b_cells.py::test_r_pe_bench_15_one_changed_cell_or_point_is_singular" \
  "tests/test_b103_inc9_b_detail.py::test_r_pe_bench_66_one_notice_is_singular" \
  "tests/test_b103_inc9_b_detail.py::test_r_pe_bench_50_2_the_curve_op_line" \
  "tests/test_b103_inc9_b_detail.py::test_r_pe_bench_50_3_the_unit_follows_the_input" \
  "tests/test_b103_inc9_w_stage.py::test_r_pe_bench_15_16_18_the_painted_row_shows_mark_new_count_and_delta_after_an_apply_and_a_stage" \
  "tests/test_b103_inc9_b_detail.py::test_r_pe_bench_21_a_refused_decode_says_refused_not_decoding"
echo "B fx9b red (4c891ea9 product + head tests): $(sumline b-fx9b-red.txt)" >> $L
./run.sh $S/cb21d5517 b-fx9d-red.txt -n 0 -rfE tests/test_b103_inc9_ob_json_view.py
echo "B fx9d red (b21d5517 product + O-B test): $(sumline b-fx9d-red.txt)" >> $L
E="env -i PATH=/usr/bin:/bin HOME=$S/home/$RUNNER_HOME_NAME TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=."
for t in head moc1 moc2; do (cd $S/$t && $E $PY $S/card_diff.py 3000 > $S/out/cd-$t.txt 2>&1); done
for m in moc1 moc2; do echo "B card_diff $m vs head: $(diff <(tail -n +2 out/cd-head.txt) <(tail -n +2 out/cd-$m.txt) | grep -c '^>') differing digests of $(tail -n +2 out/cd-head.txt | wc -l)" >> $L; done
./run.sh $S/moc1 b-moc1-card.txt -n 2 -rfE tests/test_tui_patch_card.py
echo "B oc1 test_tui_patch_card: $(sumline b-moc1-card.txt)" >> $L
./run.sh $S/mod1 b-mod1.txt -n 2 -rfE tests/test_b103_inc9_w_stage.py tests/test_b103_inc9_b_cells.py
echo "B od1 w_stage+b_cells: $(sumline b-mod1.txt)" >> $L
./run.sh $S/mod2 b-mod2.txt -n 2 -rfE -m "not serial_timing and not slow" tests/test_b103_inc9_w_stage.py tests/test_b103_inc9_b_cells.py tests/test_b103_inc9_w_select.py tests/test_b103_inc9_w_mutants.py tests/test_b103_inc9_w_keys.py
echo "B od2 w_stage+b_cells+w_select+w_mutants+w_keys: $(sumline b-mod2.txt)" >> $L
echo "C start $(date)" >> $L
for f in head/tests/test_b103_inc9_*.py; do b=$(basename $f .py)
  ./run.sh $S/head c-$b.txt -n 2 -rfE -m "not serial_timing and not slow" tests/$b.py; echo "C $b: $(sumline c-$b.txt)" >> $L; done
TMO=1800 ./run.sh $S/head c-inc9-slow.txt -n 0 -rfE -m "slow and not serial_timing" $(cd head && ls tests/test_b103_inc9_*.py)
echo "C inc9 slow (not timing): $(sumline c-inc9-slow.txt)" >> $L
for f in head/tests/test_b103_inc8_*.py; do b=$(basename $f .py)
  ./run.sh $S/head c-$b.txt -n 2 -rfE tests/$b.py; echo "C $b: $(sumline c-$b.txt)" >> $L; done
for b in test_id_registry test_suite_hygiene test_requirements_canon test_address_census test_deps_seam_law test_no_private_tokens test_engine_unchanged; do
  TMO=900 ./run.sh $S/head c-$b.txt -n 2 -rfE tests/$b.py; echo "C law $b: $(sumline c-$b.txt) | $(grep '^FAILED' out/c-$b.txt | tr '\n' ' ')" >> $L; done
echo "D start $(date)" >> $L
for t in head cb21d5517 c16b00234 c6c4fd21f; do
  ./run.sh $S/$t d-hs-$t.txt -n 0 -rfEs tests/test_tui_patch_history_strip.py
  echo "D history_strip $t: $(sumline d-hs-$t.txt) | $(grep -E '^(FAILED|SKIPPED)' out/d-hs-$t.txt | cut -c1-160 | tr '\n' ' ')" >> $L; done
for b in test_tui_patch_card test_tui_patch_json test_b100_session_reset test_b103_clipboard_core test_b103_copy_paste_matrix test_b97_chips_help test_b99_editor_image test_tui_patch_editor_b94 test_tui_snapshot; do
  for t in head c16b00234 c6c4fd21f; do
    TMO=900 ./run.sh $S/$t d-$b-$t.txt -n 2 -rfE tests/$b.py
    grep '^FAILED' out/d-$b-$t.txt | sed 's/ - .*//' | sort > out/f-$b-$t.txt
    echo "D $b $t: $(sumline d-$b-$t.txt) | failed $(wc -l < out/f-$b-$t.txt)" >> $L; done
  echo "D $b head-vs-16b00234 diff lines: $(diff out/f-$b-head.txt out/f-$b-c16b00234.txt | grep -c '^[<>]'); head-vs-6c4fd21f: $(diff out/f-$b-head.txt out/f-$b-c6c4fd21f.txt | grep -c '^[<>]')" >> $L
done
echo "end $(date)" >> $L; echo CHAIN_DONE >> $L
