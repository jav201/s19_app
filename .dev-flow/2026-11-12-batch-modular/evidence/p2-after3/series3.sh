#!/usr/bin/env bash
# P2 after3: serial 3x per tree (BEFORE then AFTER alternating) for the passed->failed candidates; idle runner.
set -u
Z=~/work/zq-mod; PY=$HOME/miniconda3/envs/s19ci/bin/python; S=$Z/ser3; rm -rf $S; mkdir -p $S/zq_iso_user $S/tmp
N=(
"tests/test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second[mac-sync]"
"tests/test_b100_save_dialog.py::test_tc_b100_65_summary_rows_equal_the_plan[merge]"
"tests/test_b100_save_dialog.py::test_tc_b100_65_active_variant_change_counts_as_out_of_date"
)
E="env -i PATH=/usr/bin:/bin HOME=$S/zq_iso_user TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8 TERM=xterm-256color"
for n in "${N[@]}"; do
  line="$n"
  for i in 1 2 3; do
    for t in before after3; do
      r=$(cd $Z/$t/tree && $E $PY -m pytest -q -p no:cacheprovider "$n" < /dev/null 2>&1 | tail -1)
      case "$r" in *" passed"*) o=P;; *) o=F;; esac
      line="$line ${t:0:1}$i:$o"
    done
  done
  echo "$line"
done
rm -rf $S
echo SERIES_DONE
