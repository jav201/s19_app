#!/usr/bin/env bash
# Launcher (setsid nohup must not be started inline through ssh).  Usage: launch-vf.sh [k ...]
P=~/work/zq-mod/p5nc
cd $P && setsid nohup bash $P/evidence/nc_vf3.sh $P/tree "$@" > $P/evidence/nc-vf3.log 2>&1 < /dev/null &
echo launched
