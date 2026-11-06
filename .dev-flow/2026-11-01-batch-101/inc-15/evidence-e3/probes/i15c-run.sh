#!/usr/bin/env bash
# usage: i15c-run.sh <run-name> <pytest args...>  (LAN laptop, /tmp/i15c/wt = m4snap-main = c2cba35)
set -u
name="$1"; shift
mkdir -p /tmp/i15c/runs/$name
cd /tmp/i15c/wt || exit 2
env -u NO_COLOR PYTHONPATH=/tmp/i15c/scripts \
  /data/miniconda3/envs/s19ci/bin/python -m pytest -p i15c_guard -p no:cacheprovider \
  --basetemp=/tmp/i15c/runs/$name/bt "$@"
