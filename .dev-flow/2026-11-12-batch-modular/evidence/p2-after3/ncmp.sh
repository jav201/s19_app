#!/usr/bin/env bash
# NC-CMP-1 / NC-CMP-2 / B4 drop on the final comparator (after3 tree); scratch removed at the end.
set -u
Z=~/work/zq-mod; PY=$HOME/miniconda3/envs/s19ci/bin/python; T=$Z/after3/tree; S=$Z/ncmp; rm -rf $S; mkdir -p $S
A=$Z/after3/outcomes.tsv; FAM=test_ac1_no_tui_module_constructs_a_stock_input
C="$PY -I $T/tools/modularize/compare_outcomes.py $Z/before/outcomes.tsv"
R="--before-rc $Z/before/rc --after-rc $Z/after3/rc --flaky $Z/flaky3.txt --families $Z/families.txt --tree $T"
run(){ echo "== $1 ($2)"; $C $3 $R 2>&1 | grep -E "^COMPARE|^B[1-4]" | grep -vE "^B1 tests/test_package_source_helper|^B2 .*(failed|skipped) -> passed" ; echo "rc=${PIPESTATUS[0]}"; }
cd $T
run baseline "after3 as is" $A
# NC-CMP-1: drop one non-family line
grep -v "$FAM" $A | head -1 | cut -f1 > $S/drop1; grep -vF -f $S/drop1 $A > $S/nc1.tsv; run NC-CMP-1 "dropped $(cat $S/drop1)" $S/nc1.tsv
# NC-CMP-2: flip one passed outcome to failed
id=$(grep -v "$FAM" $A | grep -P "\tpassed$" | head -1 | cut -f1); awk -F'\t' -v id="$id" 'BEGIN{OFS="\t"} $1==id{$2="failed"}1' $A > $S/nc2.tsv; run NC-CMP-2 "flipped $id" $S/nc2.tsv
# TC-62: drop one id of the paste family
grep "$FAM" $A | head -1 | cut -f1 > $S/drop4; grep -vF -f $S/drop4 $A > $S/nc4.tsv; run TC-62-B4 "dropped $(cat $S/drop4)" $S/nc4.tsv
rm -rf $S
echo NCMP_DONE
