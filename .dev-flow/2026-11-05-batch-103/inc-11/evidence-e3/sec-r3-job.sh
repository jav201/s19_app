#!/bin/bash
# usage: sec-r3-job.sh <out name> <script> [args...] -- transcript header/footer around sec-r3-run.sh
S=/tmp/b103-e3r3-11-S
out="$S/out-$1.txt"; shift
{
  echo "# $* $(date -Iseconds) host $(hostname) clone $(git -C ~/work/s19_app rev-parse --short HEAD) status $(git -C ~/work/s19_app status --short | wc -l) changed; corpus files $(ls ~/a2l-corpus/files | wc -l) (read-only); load $(cut -d' ' -f1-3 /proc/loadavg)"
  bash $S/scripts/sec-r3-run.sh "$@"
  echo "# exit $? ; clone status after: $(git -C ~/work/s19_app status --short | wc -l) changed"
} > "$out" 2>&1
