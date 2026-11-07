#!/bin/bash
# Round-4 chains on <runner>. usage: sec-r4-chain.sh timing|check
# timing: the timing modes one after another (serial); check: correctness, determinism and memory modes.
cd /tmp/b103-e5r4-4-sec || exit 1
if [ "$1" = timing ]; then
  for m in shapes4 dear cheap boundary; do ./sec-r4-run.sh r4 "$m"; done
  for m in perf paste; do ./sec-r4-run.sh r1 "$m"; done
else
  ./sec-r4-run.sh r4 nonascii
  ./sec-r4-run.sh r4 check4
  for s in 0 1 4242 random; do ./sec-r4-run.sh r4 det4 "$s"; done
  for s in 0 1 4242 random; do ./sec-r4-run.sh r1 det "$s"; done
  ./sec-r4-run.sh r1 mem
fi
echo "CHAIN $1 DONE"
