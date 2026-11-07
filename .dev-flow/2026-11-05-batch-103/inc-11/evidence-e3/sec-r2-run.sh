#!/bin/bash
# usage: run.sh <script> [args...]  -- isolated env, read-only clone and corpus, no bytecode writes
S=/tmp/b103-e3r2-11-S
export HOME=$S/<user> XDG_CONFIG_HOME=$S/<user>/.config XDG_DATA_HOME=$S/<user>/.local/share XDG_CACHE_HOME=$S/<user>/.cache LOCALAPPDATA=$S/<user>/lad PYTHONDONTWRITEBYTECODE=1
mkdir -p $HOME $S/work
cd $S
ulimit -v 8000000
exec /home/<user>/miniconda3/envs/s19ci/bin/python -I "$@" < /dev/null
