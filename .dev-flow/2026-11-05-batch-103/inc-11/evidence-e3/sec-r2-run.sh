#!/bin/bash
# usage: run.sh <script> [args...]  -- isolated env, read-only clone and corpus, no bytecode writes
S=/tmp/b103-e3r2-11-S
export HOME=$S/zq_iso_user XDG_CONFIG_HOME=$S/zq_iso_user/.config XDG_DATA_HOME=$S/zq_iso_user/.local/share XDG_CACHE_HOME=$S/zq_iso_user/.cache LOCALAPPDATA=$S/zq_iso_user/lad PYTHONDONTWRITEBYTECODE=1
mkdir -p $HOME $S/work
cd $S
ulimit -v 8000000
exec /home/javiergr/miniconda3/envs/s19ci/bin/python -I "$@" < /dev/null
