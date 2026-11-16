#!/bin/bash
# FX9d chain 4: fresh clone at the final code head; the id-registry law and the new file again.
S=~/work/zq-fx9d; cd $S && rm -rf clone2 && git clone -q -b b103-inc9 fx9d2.bundle clone2 || exit 9
L=$S/out/chain4-log.txt; echo "clone2 $(cd clone2 && git log --oneline -1 | cut -c1-8)" > $L
for b in test_id_registry test_b103_inc9_ob_json_view test_suite_hygiene test_requirements_canon; do
  ./run.sh $S/clone2 c4-$b.txt -q -n 2 tests/$b.py
  echo "$b $(grep -E 'passed|failed|error' out/c4-$b.txt | tail -1)" >> $L
done
echo CHAIN4_DONE >> $L
