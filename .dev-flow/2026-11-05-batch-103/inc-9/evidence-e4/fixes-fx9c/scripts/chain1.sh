#!/bin/bash
# FX9c chain 1 (probes, then timing): trees by git archive of each option's commit (LF on Linux), FX9b's probes and
# the FX9c probe copied into each tree's tests/ (scratch only, HT-09); every timed run waits for a 1-min load < 2.
export RUNNER_HOME_NAME="${RUNNER_HOME_NAME_FROM_CALLER:?}"   # HT-02 basename; never spelled in records (HT-11)
S=~/work/zq-fx9c; cd $S
PY=~/miniconda3/envs/s19ci/bin/python
L=out/chain1-log.txt; mkdir -p out; echo "start $(date)" > $L
rm -rf repo && git clone -q -b b103-inc9 fx9c.bundle repo || exit 9
for spec in "base 16b00234" "oc 8bd07d0c" "od f5cb522e"; do
  set -- $spec; rm -rf $1 && mkdir $1 && (cd repo && git archive $2) | tar -x -C $1
  cp test_fx9b_probe.py test_fx9b_probe2.py test_fx9c_probe.py $1/tests/
done
cp -r od marr && $PY -I mutant-arrival.py marr
cp -r od mstall && $PY -I mutant-stall.py mstall
diff -r od/s19_app marr/s19_app > out/t-marr-diff.txt; diff -r od/s19_app mstall/s19_app > out/t-mstall-diff.txt
E="env -i PATH=/usr/bin:/bin HOME=$S/home/$RUNNER_HOME_NAME TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=."
mkdir -p home/$RUNNER_HOME_NAME tmp
for t in base oc; do (cd $t && $E $PY $S/card_diff.py 3000 > $S/out/cd-$t.txt 2>&1); done
echo "card_diff: base $(wc -l < out/cd-base.txt) lines, oc $(wc -l < out/cd-oc.txt) lines, diff (minus the __file__ line): $(diff <(tail -n +2 out/cd-base.txt) <(tail -n +2 out/cd-oc.txt) | wc -l)" >> $L
for spec in "base 0" "oc 0" "od 0" "od 1"; do
  set -- $spec
  l=$(./waitload.sh) || { echo "parts $1 nobracket=$2: not measured (load $l)" >> $L; continue; }
  FX9C_NOBRACKET=$2 TMO=600 ./run.sh $S/$1 p-$1-nb$2.txt -n 0 -s tests/test_fx9c_probe.py
  echo "parts $1 nobracket=$2 (load before $l): $(grep -E '(passed|failed|error)' out/p-$1-nb$2.txt | tail -1)" >> $L
done
J=tests/test_b103_inc9_w_jobs.py
for spec in "od 29_1" "od 29_2" "od 82_1" "od 20_1" "marr 29_2" "mstall 29_2" "mstall 82_1"; do
  set -- $spec
  l=$(./waitload.sh) || { echo "$1 $2: not measured (load $l)" >> $L; continue; }
  TMO=600 ./run.sh $S/$1 t-$1-$2.txt -n 0 -m serial_timing -k "test_r_pe_bench_${2}_" $J
  echo "$1 $2 (load before $l): $(grep -E '(passed|failed|error)' out/t-$1-$2.txt | tail -1) | $(grep -oE '(slowest press|right) [0-9.]+ s[^\"]*' out/t-$1-$2.txt | head -1)" >> $L
done
echo "end $(date)" >> $L; echo CHAIN1_DONE >> $L
