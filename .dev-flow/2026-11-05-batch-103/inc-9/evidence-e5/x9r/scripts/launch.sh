#!/bin/bash
# PF-02: detached launch on the host; RUNNER_HOME_NAME set here only (HT-11).
cd ~/work/zq-x9r && RUNNER_HOME_NAME=<runner-home> setsid nohup bash -c "./setup.sh > out/setup.log 2>&1 && ./chain.sh" > out/launch.log 2>&1 < /dev/null &
echo "pid $!"
