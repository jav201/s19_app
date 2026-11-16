#!/bin/bash
# FX9f battery on the fresh clone (HT-03): Inc 9 files (not timing, incl. slow), Inc 8 files, laws; one file per run.
S=~/work/zq-fx9f; cd $S; L=out/battery-log.txt; echo "start $(date)" > $L
sumline() { grep -E '(passed|failed|error)( in|,)' out/$1 | tail -1; }
for f in head/tests/test_b103_inc9_*.py; do b=$(basename $f .py)
  TMO=1800 ./run.sh $S/head c-$b.txt -n 2 -rfE -m "not serial_timing" tests/$b.py; echo "inc9 $b: $(sumline c-$b.txt)" >> $L; done
for f in head/tests/test_b103_inc8_*.py; do b=$(basename $f .py)
  ./run.sh $S/head c-$b.txt -n 2 -rfE tests/$b.py; echo "inc8 $b: $(sumline c-$b.txt)" >> $L; done
for b in test_id_registry test_suite_hygiene test_requirements_canon test_address_census test_deps_seam_law test_no_private_tokens test_engine_unchanged; do
  TMO=900 ./run.sh $S/head c-$b.txt -n 2 -rfE tests/$b.py; echo "law $b: $(sumline c-$b.txt) | $(grep '^FAILED' out/c-$b.txt | cut -c1-120 | tr '\n' ' ')" >> $L; done
echo "end $(date)" >> $L; echo BATTERY_DONE >> $L
