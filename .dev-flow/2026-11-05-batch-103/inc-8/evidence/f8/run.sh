#!/bin/bash
# usage: run.sh <tree-dir-under-zq-f8> <out-file> <pytest args...>
S=~/work/zq-f8
T=$S/$1; OUT=$S/$2; shift 2
ISO=runner; ISO=${ISO}_iso  # HT-02 basename, built at run time (the redaction law adopts it as an identity)
mkdir -p $S/home/$ISO $S/x/config $S/x/cache $S/x/data $S/tmp
cd $T || exit 9
E="env -i PATH=/usr/bin:/bin HOME=$S/home/$ISO XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=."
PY=~/miniconda3/envs/s19ci/bin/python
{
  echo "TREE $1 $(date -u +%FT%TZ) load: $(cut -d' ' -f1-3 /proc/loadavg)"
  $E $PY -c "import sys; sys.path.insert(0, '.'); import s19_app; print(s19_app.__file__)" < /dev/null
  $E timeout 300 $PY -m pytest -p no:cacheprovider "$@" < /dev/null
  echo "RC=$?"
} > $OUT 2>&1
