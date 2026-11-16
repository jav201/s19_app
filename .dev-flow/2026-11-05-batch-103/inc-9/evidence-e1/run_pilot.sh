#!/bin/bash
# Inc 9 E1 pilot launcher on the Linux runner (HT-02 isolated env, HOME basename from RUNNER_HOME_NAME, the HT-02 basename).
S=~/work/zq-i9/s
rm -rf "$S"; mkdir -p "$S/home/$RUNNER_HOME_NAME" "$S/x/config" "$S/x/data" "$S/x/cache" "$S/tmp"
cd ~/work/zq-i9/clone
uptime
timeout 600 env -i PATH=/usr/bin:/bin HOME=$S/home/$RUNNER_HOME_NAME XDG_CONFIG_HOME=$S/x/config XDG_DATA_HOME=$S/x/data XDG_CACHE_HOME=$S/x/cache LOCALAPPDATA=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -B -I ~/work/zq-i9/pilot_inc9.py "$S" < /dev/null
echo "exit=$?"
