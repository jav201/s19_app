#!/bin/bash
# PF-02: launched detached on the host; chain1 (probes + timing) then chain2 (fresh clone battery).
cd ~/work/zq-fx9c && setsid nohup bash -c './chain1.sh; ./chain2.sh' > out/launch.log 2>&1 < /dev/null &
echo "pid $!"
