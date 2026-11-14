#!/usr/bin/env bash
# Detached launcher (PF-02). Usage: launch.sh <name> <script> <args...>; prints the PID (= SID).
S=$HOME/work/zq-base2
NAME="$1"; shift
setsid nohup bash "$@" > "$S/$NAME.launch.log" 2>&1 < /dev/null &
echo "$!" > "$S/$NAME.pid"
echo "launched $NAME pid=$!"
