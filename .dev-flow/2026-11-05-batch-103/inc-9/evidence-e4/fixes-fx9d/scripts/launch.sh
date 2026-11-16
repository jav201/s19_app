#!/bin/bash
# PF-02: detached launch on the host.
cd ~/work/zq-fx9d && RUNNER_HOME_NAME=<runner-home> setsid nohup ./chain2.sh > out/launch.log 2>&1 < /dev/null &
echo "pid $!"
