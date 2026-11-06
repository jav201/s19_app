#!/usr/bin/env bash
# usage: i15-hold.sh : each node under its held handler, 2 reps (Linux, /tmp/i15/wt)
set -u
mkdir -p /tmp/i15/runs
N1=tests/test_tui_patch_editor_v2.py::test_tc331_disable_guard_predicate_tracks_source_path
N2=tests/test_tui_flow_execution_b94.py::test_tc_b94_27_lane_binding_isolation_and_noop
for i in 1 2; do
  I15_HOLD=fx_bind /tmp/i15/i15-run.sh "lin-hold-fxbind-$i" -v "$N2" > "/tmp/i15/runs/lin-hold-fxbind-$i.log" 2>&1
  echo "lin-hold-fxbind-$i rc=$? $(grep -E '^E +(assert|AssertionError)' /tmp/i15/runs/lin-hold-fxbind-$i.log | head -2 | tr '\n' ' ')"
  I15_HOLD=patch_action /tmp/i15/i15-run.sh "lin-hold-patch-$i" -v "$N1" > "/tmp/i15/runs/lin-hold-patch-$i.log" 2>&1
  echo "lin-hold-patch-$i rc=$? $(grep -E '^E +(assert|AssertionError|textual)' /tmp/i15/runs/lin-hold-patch-$i.log | head -2 | tr '\n' ' ')"
done
