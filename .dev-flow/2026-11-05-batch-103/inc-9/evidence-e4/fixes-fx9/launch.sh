#!/bin/bash
# usage: launch.sh <script> : start it detached (PF-02), print its PID
cd ~/work/zq-fx9 || exit 9
setsid nohup "./$1" > "out/$1.nohup" 2>&1 < /dev/null &
echo "PID $!"
