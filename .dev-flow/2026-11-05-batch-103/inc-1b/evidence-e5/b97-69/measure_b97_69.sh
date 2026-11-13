#!/usr/bin/env bash
# Measure TC-B97-69 pass rate on two exact trees (head vs base), N runs each.
# Usage: measure_b97_69.sh <work_root> <bundle> <head_sha> <base_sha> <n_node> <n_file>
set -u
ROOT="$1"; BUNDLE="$2"; HEAD_SHA="$3"; BASE_SHA="$4"; NN="$5"; NF="$6"
PY="$HOME/miniconda3/envs/s19ci/bin/python"
NODE="tests/test_b97_key_bar.py::test_tc_b97_69_page_keys_do_nothing_where_disabled"
mkdir -p "$ROOT"
run_tree() {
  local tag="$1" sha="$2" tree="$ROOT/tree-$1" st="$ROOT/state-$1"
  rm -rf "$tree" "$st"
  git clone -q "$BUNDLE" "$tree" && git -C "$tree" checkout -q "$sha" || { echo "$tag CLONE_FAIL" > "$ROOT/$tag.summary"; return; }
  mkdir -p "$st/zq_iso_user" "$st/xdg" "$st/tmp"
  local log="$ROOT/$tag.log"; : > "$log"
  local envs=(env -i PATH="/usr/bin:/bin" HOME="$st/zq_iso_user" XDG_CONFIG_HOME="$st/xdg/c"
      XDG_DATA_HOME="$st/xdg/d" XDG_CACHE_HOME="$st/xdg/k" XDG_STATE_HOME="$st/xdg/s" TMPDIR="$st/tmp"
      PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 TERM=xterm-256color)
  local np=0 nf=0 fp=0 ff=0
  for i in $(seq 1 "$NN"); do
    local t0=$(date +%s.%N)
    (cd "$tree" && "${envs[@]}" "$PY" -c "import sys; sys.path.insert(0,'.'); import s19_app; print(s19_app.__file__); import pytest; sys.exit(pytest.main(['-q','-p','no:cacheprovider','--tb=line','$NODE']))" < /dev/null) > "$ROOT/$tag-node-$i.txt" 2>&1
    local rc=$? t1=$(date +%s.%N)
    if [ $rc -eq 0 ]; then np=$((np+1)); else nf=$((nf+1)); fi
    echo "$tag node run=$i rc=$rc secs=$(awk "BEGIN{print $t1-$t0}")" >> "$log"
  done
  for i in $(seq 1 "$NF"); do
    (cd "$tree" && "${envs[@]}" "$PY" -c "import sys; sys.path.insert(0,'.'); import s19_app; print(s19_app.__file__); import pytest; sys.exit(pytest.main(['-q','-p','no:cacheprovider','--tb=line','tests/test_b97_key_bar.py']))" < /dev/null) > "$ROOT/$tag-file-$i.txt" 2>&1
    local rc=$?
    if grep -q "test_tc_b97_69.*FAILED\|FAILED.*test_tc_b97_69" "$ROOT/$tag-file-$i.txt"; then ff=$((ff+1)); else fp=$((fp+1)); fi
    echo "$tag file run=$i rc=$rc tail=$(tail -1 "$ROOT/$tag-file-$i.txt")" >> "$log"
  done
  echo "$tag sha=$sha node_pass=$np node_fail=$nf file_b97_69_pass=$fp file_b97_69_fail=$ff" > "$ROOT/$tag.summary"
}
run_tree head "$HEAD_SHA" &
run_tree base "$BASE_SHA" &
wait
cat "$ROOT"/*.summary
echo MEASURE_DONE
