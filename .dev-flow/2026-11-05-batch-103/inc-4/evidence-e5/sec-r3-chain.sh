#!/bin/bash
# Round-3 chains on <runner>. usage: sec-r3-chain.sh timing|check
# timing: the timing modes one after another (serial); check: correctness and memory modes.
cd /tmp/b103-e5r3-4-sec || exit 1
if [ "$1" = timing ]; then
  for m in walk cap shapes subs; do ./sec-r3-run.sh r3 "$m"; done
  for m in perf paste; do ./sec-r3-run.sh r1 "$m"; done
else
  ./sec-r3-run.sh r3 check
  for s in 0 1 4242 random; do ./sec-r3-run.sh r3 det3 "$s"; done
  for s in 0 1 4242 random; do ./sec-r3-run.sh r1 det "$s"; done
  ./sec-r3-run.sh r3 build37
  ./sec-r3-run.sh r3 budget
  ./sec-r3-run.sh r1 mem
fi
echo "CHAIN $1 DONE"
