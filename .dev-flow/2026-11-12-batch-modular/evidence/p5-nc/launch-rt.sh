#!/usr/bin/env bash
P=~/work/zq-mod/p5nc
cd $P && setsid nohup bash $P/evidence/nc_rt3.sh $P/tree > $P/evidence/nc-rt3.log 2>&1 < /dev/null &
echo launched
