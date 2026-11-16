#!/bin/bash
S=~/work/zq-x10
for t in exact base; do
  cp $S/diag59.py $S/$t/diag59.py; cd $S/$t
  E=(env -i PATH=/usr/bin:/bin HOME="$S/home/$RUNNER_HOME_NAME" XDG_CONFIG_HOME="$S/x/config" XDG_CACHE_HOME="$S/x/cache" XDG_DATA_HOME="$S/x/data" TMPDIR="$S/tmp" PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 PYTHONPATH=.)
  { "${E[@]}" ~/miniconda3/envs/s19ci/bin/python -c "import s19_app;print(s19_app.__file__)"; echo "tree: $(cat .x10-rev)"; echo "uptime: $(uptime)"; "${E[@]}" timeout 300 ~/miniconda3/envs/s19ci/bin/python diag59.py < /dev/null; echo "RC=$?"; } > $S/logs/diag59-$t.txt 2>&1
  rm diag59.py
done
