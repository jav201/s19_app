#!/usr/bin/env bash
set -eu
S="$HOME/work/zq-q9b"
sid=$(cat "$S/out/q9b/driver.pid")
pids=$(ps -eo pid=,sid= | awk -v wanted="$sid" '$2 == wanted {print $1}')
for pid in $pids; do
    kill -TERM "$pid"
done
sleep 2
for pid in $pids; do
    if ps -p "$pid" -o pid=,stat=,args=; then
        exit 1
    fi
done
