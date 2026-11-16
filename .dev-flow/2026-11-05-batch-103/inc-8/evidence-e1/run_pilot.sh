#!/bin/bash
S=~/work/zq-i8/s
rm -rf "$S"; mkdir -p "$S/home/${RUNNER_HOME_NAME:?set the HT-02 HOME basename}" "$S/x/config" "$S/x/data" "$S/x/cache" "$S/tmp"
cd ~/work/zq-i8/clone
timeout 300 env -i PATH=/usr/bin:/bin HOME=$S/home/$RUNNER_HOME_NAME XDG_CONFIG_HOME=$S/x/config XDG_DATA_HOME=$S/x/data XDG_CACHE_HOME=$S/x/cache LOCALAPPDATA=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -B -I ~/work/zq-i8/pilot_inc8.py "$S" < /dev/null
echo "exit=$?"
