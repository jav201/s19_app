#!/usr/bin/env bash
# usage: i15-run.sh <run-name> <pytest args...>  (Linux comparison runs, /tmp/i15/wt = c2cba35)
set -u
name="$1"; shift
mkdir -p /tmp/i15/runs/$name
cd /tmp/i15/wt || exit 2
env -u NO_COLOR PYTHONPATH=/tmp/i15/scripts \
  /data/miniconda3/envs/s19ci/bin/python -m pytest -p i15_guard -p no:cacheprovider \
  --basetemp=/tmp/i15/runs/$name/bt "$@"
