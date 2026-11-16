#!/usr/bin/env bash
P=~/work/zq-mod/p5nc
cd $P && setsid nohup bash -c "bash $P/evidence/nc_mv_e8.sh $P/tree > $P/evidence/nc-mv-e8.log 2>&1; bash $P/evidence/nc_mv37.sh $P/tree > $P/evidence/nc-mv37.log 2>&1; bash $P/evidence/nc_pkg.sh $P/tree > $P/evidence/nc-pkg.log 2>&1" > /dev/null 2>&1 < /dev/null &
echo launched
