#!/bin/bash
# FX9d chain 3: every file that failed in chain 2 re-run whole on the base tree (b21d5517), same runner; FAILED id lists compared.
S=~/work/zq-fx9d; cd $S; L=out/chain3-log.txt; : > $L
for b in $(grep -E ' [0-9]+ failed' out/chain2-log.txt | cut -d' ' -f1); do
  TMO=900 ./run.sh $S/base b-$b.txt -q -n 2 tests/$b.py
  echo "$b base: $(grep -E 'passed|failed|error' out/b-$b.txt | tail -1)" >> $L
  grep '^FAILED' out/c-$b.txt | sed 's/ - .*//' | sort > out/f-c.txt; grep '^FAILED' out/b-$b.txt | sed 's/ - .*//' | sort > out/f-b.txt
  echo "$b failed-id diff clone vs base: $(diff out/f-c.txt out/f-b.txt | wc -l) lines" >> $L
done
echo CHAIN3_DONE >> $L
