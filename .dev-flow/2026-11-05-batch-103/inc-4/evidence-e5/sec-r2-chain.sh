#!/bin/bash
# Round-2 chains on cachyos-rtx. usage: sec-r2-chain.sh timing|check
# timing: the timing modes one after another (serial); check: correctness modes (exceptions, spans, oracle, seeds).
cd /tmp/b103-e5-4-sec-r2 || exit 1
if [ "$1" = timing ]; then
  for m in dense craft band switch fixcheck subkey; do ./sec-r2-run.sh r2 "$m"; done
  for m in perf paste adv; do ./sec-r2-run.sh r1 "$m"; done
else
  ./sec-r2-run.sh r2 fuzz
  for s in 0 1 4242 random; do ./sec-r2-run.sh r1 det "$s"; done
  for m in caps spans mem; do ./sec-r2-run.sh r1 "$m"; done
fi
echo "CHAIN $1 DONE"
