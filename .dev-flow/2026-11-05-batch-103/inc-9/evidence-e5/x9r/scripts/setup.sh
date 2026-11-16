#!/bin/bash
# X9r trees: real git clones of the bundle (b103-inc9 + main); copies for RED and mutants (HT-09).
set -e
S=~/work/zq-x9r; cd $S
git clone -q -b b103-inc9 x9r.bundle head
git -C head branch -q main origin/main
for c in 16b00234 4c891ea9 6c4fd21f b21d5517; do
  git clone -q -b b103-inc9 x9r.bundle c$c; git -C c$c branch -q main origin/main; git -C c$c checkout -q --detach $c
done
# FX9b RED: 4c891ea9 product + head tests. FX9d RED: b21d5517 product + head's new O-B test file.
git -C c4c891ea9 checkout -q ab62093b -- tests
git -C cb21d5517 checkout -q ab62093b -- tests/test_b103_inc9_ob_json_view.py
for m in oc1 oc2 od1 od2; do mkdir m$m; git -C head archive HEAD | tar -x -C m$m; ~/miniconda3/envs/s19ci/bin/python -I -B mutate.py m$m $m; done
echo SETUP_DONE
