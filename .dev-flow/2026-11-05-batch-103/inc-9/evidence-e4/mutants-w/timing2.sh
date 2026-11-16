#!/bin/bash
# HT-08: each node only when the 1-min load < 2; serial; 45 min window from the start
S=$HOME/work/zq-mw9
cd $S
start=$(date +%s); LOG=$S/out/timing2.log; : > $LOG
echo "window start $(date) deadline +45 min" >> $LOG
for node in test_r_pe_bench_29_1 test_r_pe_bench_29_2 test_r_pe_bench_82_1; do
  ok=0
  while [ $(( $(date +%s) - start )) -lt 2700 ]; do
    l=$(cut -d' ' -f1 /proc/loadavg)
    echo "$(date +%T) $node load $l" >> $LOG
    if awk -v l=$l 'BEGIN{exit !(l<2.0)}'; then ok=1; break; fi
    sleep 20
  done
  if [ $ok = 1 ]; then
    echo "$(date +%T) RUN $node load-before $(cut -d' ' -f1 /proc/loadavg)" >> $LOG
    ./run.sh $S/clone t2-$node.txt 0 1700 "tests/test_b103_inc9_w_jobs.py" -k $node -v > /dev/null 2>&1
    echo "$(date +%T) END $node load-after $(cut -d' ' -f1 /proc/loadavg) $(tail -3 out/t2-$node.txt | tr '\n' '|')" >> $LOG
  else
    echo "$(date +%T) NOT-DECIDED $node (no quiet window before the deadline)" >> $LOG
  fi
done
echo DONE >> $LOG
touch $S/out/timing2.done
