#!/bin/bash
cd ~/work/zq-fx9c && setsid nohup ./chain3.sh > out/launch3.log 2>&1 < /dev/null &
echo "pid $!"
