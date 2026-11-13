#!/bin/bash
# after3 compare (rtx)
Z=~/work/zq-mod
PY=~/miniconda3/envs/s19ci/bin/python
T=$Z/after3/tree
cd $T
$PY -I tools/modularize/compare_outcomes.py $Z/before/outcomes.tsv $Z/after3/outcomes.tsv \
  --before-rc $Z/before/rc --after-rc $Z/after3/rc --flaky $Z/flaky4.txt \
  --families $Z/families.txt --tree $T > $Z/cmp4.txt 2>&1
echo "rc=$?" >> $Z/cmp4.txt
