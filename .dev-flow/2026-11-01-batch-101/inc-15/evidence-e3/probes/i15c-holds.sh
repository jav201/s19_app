#!/usr/bin/env bash
# usage: i15c-holds.sh : base nodes under the E3-correction hold modes, 2 reps each
set -u
F=tests/test_tui_patch_editor_v2.py
N331=$F::test_tc331_disable_guard_predicate_tracks_source_path
NAT=$F::test_at030c_directly_dropped_file_is_listed_and_loadable
NSB=$F::test_save_back_prompt
run() { # name hold action node
  I15_HOLD="$2" I15_HOLD_ACTION="$3" /tmp/i15c/scripts/i15c-run.sh "$1" -v "$4" > "/tmp/i15c/runs/$1.log" 2>&1
  echo "$1 rc=$? $(grep -E '^E +(assert|AssertionError|textual)|^(FAILED|PASSED)|passed|failed' /tmp/i15c/runs/$1.log | head -3 | tr '\n' ' ')"
}
for i in 1 2; do
  run "i15c-hold-paste-$i"   patch_action parse_paste "$N331"
  run "i15c-hold-select-$i"  change_file  ""          "$NAT"
  run "i15c-hold-apply-$i"   patch_action apply_doc   "$NSB"
  run "i15c-hold-decline-$i" save_back    decline     "$NSB"
  run "i15c-hold-confirm-$i" save_back    confirm     "$NSB"
done
