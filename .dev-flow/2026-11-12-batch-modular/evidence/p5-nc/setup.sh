#!/usr/bin/env bash
# p5-nc setup: final tree (batch-modular-apply @5b67c844) + base tree (4f721985) in a new dir.
set -u
P=~/work/zq-mod/p5nc
mkdir -p $P/state/zq_iso_user $P/state/tmp $P/scratch
[ -d $P/tree ] && { echo "tree exists"; exit 2; }
git clone -q /tmp/zq-p2c.bundle $P/tree && cd $P/tree && git checkout -q batch-modular-apply && git branch -q main origin/main
echo "tree HEAD=$(git rev-parse --short=8 HEAD) branch=$(git branch --show-current) main=$(git rev-parse --short=8 main)"
git clone -q /tmp/zq-p2c.bundle $P/base && cd $P/base && git checkout -q 4f721985
echo "base HEAD=$(git rev-parse --short=8 HEAD)"
git -C $P/tree status --porcelain | head -3; echo "tree_size=$(du -sh $P/tree | cut -f1)"
PY=/data/miniconda3/envs/s19ci/bin/python
cd $P/tree && env -i PATH=/usr/bin:/bin HOME=$P/state/zq_iso_user TMPDIR=$P/state/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8 $PY -c "import s19_app,sys;print('s19_app from',s19_app.__file__)" < /dev/null
