#!/bin/bash
cd ~/work/zq-fx9d && RUNNER_HOME_NAME=<runner-home> setsid nohup ./after2.sh > out/launch3.log 2>&1 < /dev/null &
echo "pid $!"
