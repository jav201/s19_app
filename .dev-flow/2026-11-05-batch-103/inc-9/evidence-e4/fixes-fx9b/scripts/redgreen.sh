#!/bin/bash
# FX9b RED (base 4c891ea9 + the new tests) and GREEN (base + the fixes + the tests) of the small fixes.
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
cd ~/work/zq-fx9b
rm -rf red green && cp -r base red && cp -r base green
tar -xf tests.tar -C red && tar -xf fix.tar -C green
L=out/redgreen-log.txt; echo "start $(date)" > $L
./run.sh ~/work/zq-fx9b/red rg-red.txt -n 2 $(cat nodes.txt)
echo "red: $(grep -E '(passed|failed|error)' out/rg-red.txt | tail -1)" >> $L
./run.sh ~/work/zq-fx9b/green rg-green.txt -n 2 $(cat nodes.txt)
echo "green: $(grep -E '(passed|failed|error)' out/rg-green.txt | tail -1)" >> $L
echo "end $(date)" >> $L; echo RG_DONE >> $L
