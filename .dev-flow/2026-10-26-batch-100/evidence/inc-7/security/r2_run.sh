#!/bin/sh
# run.sh <out> <script> [args...]
out=$1; shift
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=C:/Users/jjgh8/Github/s19_app-b100-inc7 C:/Users/jjgh8/anaconda3/envs/s19env/python.exe "$@" > "$out" 2>&1
echo "exit=$?" >> "$out"
