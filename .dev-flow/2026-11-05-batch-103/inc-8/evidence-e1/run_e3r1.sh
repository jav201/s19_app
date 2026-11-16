#!/bin/bash
# Inc 8 E3R1 runner driver: isolated env (HT-02), HOME basename from $RUNNER_HOME_NAME, closed stdin.
# Arg: the step (examples | examples2 | census | cases | trace). Scratch: ~/work/zq-e3r1-8.
W=${ZQ:-~/work/zq-e3r1-8}; S=$W/s; C=$W/clone; I=.dev-flow/2026-11-05-batch-103/inc-8
PY=~/miniconda3/envs/s19ci/bin/python
mkdir -p "$S/home/${RUNNER_HOME_NAME:?set the HT-02 HOME basename}" "$S/x/config" "$S/x/data" "$S/x/cache" "$S/tmp"
ENV="env -i PATH=$(dirname $PY):/usr/bin:/bin HOME=$S/home/$RUNNER_HOME_NAME XDG_CONFIG_HOME=$S/x/config XDG_DATA_HOME=$S/x/data XDG_CACHE_HOME=$S/x/cache LOCALAPPDATA=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8"
cd "$C"
echo "uptime: $(uptime)"
case "$1" in
  examples) timeout 300 $ENV $PY -B -I "$I/evidence-e1/examples_e3r1.py" "$S" < /dev/null; echo "exit=$?" ;;
  examples2) timeout 300 $ENV $PY -B -I "$I/evidence-e1/examples_e3r2.py" < /dev/null; echo "exit=$?" ;;
  census) timeout 300 $ENV bash "$I/evidence-e1/cw-e3r1.sh" "$C" "$W/code-wire" "$S" "$C/$I/evidence-e1/cw-e3r1-graph.md" < /dev/null; echo "exit=$?" ;;
  cases) timeout 300 $ENV $PY -B -I "$I/evidence-e1/cases.py" "$I/02-test-cases.md" < /dev/null; echo "exit=$?" ;;
  trace) shift; timeout 300 $ENV $PY -B -I "$W/skill/trace_check.py" "$@" < /dev/null; echo "exit=$?" ;;
esac
