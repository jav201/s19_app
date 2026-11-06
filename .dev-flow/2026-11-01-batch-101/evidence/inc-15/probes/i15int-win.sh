#!/usr/bin/env bash
# usage: i15int-win.sh <first-run-number> <reps>  (Windows host, Git Bash; serial)
set -u
first="$1"; reps="$2"
WT=<HOME>/Github/s19_app-b101-inc15
BASE=<HOME>/.claude/jobs/3f13b036/tmp/i15int-win
PY=<HOME>/anaconda3/envs/s19env/python.exe
F=tests/test_tui_patch_editor_v2.py
NODES="$F::test_tc331_disable_guard_predicate_tracks_source_path $F::test_at030c_directly_dropped_file_is_listed_and_loadable $F::test_save_back_prompt tests/test_tui_flow_execution_b94.py::test_tc_b94_27_lane_binding_isolation_and_noop"
w() { cygpath -w "$1"; }
cd "$WT" || exit 2
export I15INT_COMMIT="$(git rev-parse --short HEAD) (Windows worktree)"
for k in $(seq 0 $((reps - 1))); do
  name=int-$(printf %02d $((first + k)))
  root=$BASE/$name
  rm -rf "$root"; mkdir -p "$root/Local" "$root/Roaming" "$root/Temp" "$root/Home" "$root/bt"
  log=$BASE/$name.log
  {
    echo "# $name: Windows serial run $((k + 1)) of $reps, the 4 Inc 15 nodes (R-TST-156)"
    echo "# cmd: python -m pytest -p i15int_guard -p no:cacheprovider -v <4 nodes>"
    env -u NO_COLOR \
      LOCALAPPDATA="$(w "$root/Local")" APPDATA="$(w "$root/Roaming")" \
      TEMP="$(w "$root/Temp")" TMP="$(w "$root/Temp")" \
      USERPROFILE="$(w "$root/Home")" HOME="$(w "$root/Home")" \
      PYTHONPATH="$(w <HOME>/.claude/jobs/3f13b036/tmp/i15int)" I15INT_TREE=s19_app-b101-inc15 \
      "$PY" -m pytest -p i15int_guard -p no:cacheprovider --basetemp="$(w "$root/bt")" -v $NODES 2>&1
    echo "# rc=$?"
  } > "$log"
  echo "$name $(grep -E '^=+ .*(passed|failed|error)' "$log" | tail -1) $(grep -E '^FAILED' "$log" | tr '\n' ' ')"
  if ! grep -q 's19_app-b101-inc15\\s19_app\\__init__.py' "$log"; then
    echo "ABORT: s19_app.__file__ is not in the worktree"; grep 's19_app.__file__' "$log"; exit 3
  fi
done
