#!/bin/bash
# run a dwell node N times while 20 CPU burners run; $1 = module, $2 = runs
cd ~/s19fix3
unset NO_COLOR; export PYTHONDONTWRITEBYTECODE=1
pids=()
for i in $(seq 20); do timeout 900 python3 -c "while 1: pass" & pids+=($!); done
for r in $(seq "$2"); do
  timeout 600 ~/s19venv/bin/python -m pytest -q -p no:cacheprovider "$1::test_tc_b97_64_a_new_set_run_restarts_the_dwell" 2>&1 | grep -E "AssertionError: \(|passed|failed" | head -2
done
kill "${pids[@]}" 2>/dev/null
wait 2>/dev/null
echo done
