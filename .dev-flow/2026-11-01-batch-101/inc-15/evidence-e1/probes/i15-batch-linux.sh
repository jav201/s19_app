#!/usr/bin/env bash
# usage: i15-batch.sh <mode: native|quantized|zero> <reps> [tag]
set -u
mode="$1"; reps="$2"; tag="${3:-}"
mkdir -p /tmp/i15/runs
N1=tests/test_tui_patch_editor_v2.py::test_tc331_disable_guard_predicate_tracks_source_path
N2=tests/test_tui_flow_execution_b94.py::test_tc_b94_27_lane_binding_isolation_and_noop
for i in $(seq 1 "$reps"); do
  name="lin-$mode$tag-$i"
  if [ "$mode" = native ]; then pm=""; else pm="$mode"; fi
  I15_PAUSE="$pm" /tmp/i15/i15-run.sh "$name" -v "$N1" "$N2" > "/tmp/i15/runs/$name.log" 2>&1
  rc=$?
  echo "$name rc=$rc failed: $(grep -E '^FAILED' "/tmp/i15/runs/$name.log" | sed 's/.*:://' | tr '\n' ' ')"
done
