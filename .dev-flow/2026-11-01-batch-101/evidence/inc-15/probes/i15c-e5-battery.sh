#!/usr/bin/env bash
# usage: i15c-e5-battery.sh  (LAN Linux host; the worktree ~/work/s19_i15c is never mutated)
# Needs /tmp/i15c/scripts/{i15c-e5-run.sh,i15c_e5_guard.py,i15c_e5_mutate.py,b94-5054743.py,hygiene-5054743.py}
set -u
S=/tmp/i15c/scripts
R=$S/i15c-e5-run.sh
WT=$HOME/work/s19_i15c
PY=/data/miniconda3/envs/s19ci/bin/python
export I15C_B94_BASE=$S/b94-5054743.py I15C_HY_BASE=$S/hygiene-5054743.py
F_PE=tests/test_tui_patch_editor_v2.py
F_B94=tests/test_tui_flow_execution_b94.py
F_HY=tests/test_suite_hygiene.py
N331=$F_PE::test_tc331_disable_guard_predicate_tracks_source_path
NAT=$F_PE::test_at030c_directly_dropped_file_is_listed_and_loadable
NSB=$F_PE::test_save_back_prompt
N27=$F_B94::test_tc_b94_27_lane_binding_isolation_and_noop
NG=$F_HY::test_r_tst_154_155_inc15_arms_wait_through_settled
NC=$F_HY::test_r_tst_007_conventions_hold_each_test_rule
N=0
run() { N=$((N + 1)); $R "$1" "e5c-$(printf %02d $N)" "$2" "${@:3}"; }
mk() { # name [controls...] : copy of the worktree (no .git) with the controls applied
  local d=/tmp/i15c/trees/$1; shift
  rm -rf "$d"; mkdir -p "$d"
  rsync -a --exclude .git --exclude __pycache__ "$WT/" "$d/"
  [ $# -gt 0 ] && $PY $S/i15c_e5_mutate.py "$d" "$@" >&2
  echo "$d"
}

echo "== A: GREEN in the worktree (e5c-01 .. 06)"
run $WT "changed files, parallel lane -n 8 (R-TST-157/2, C-8)" -q -rs -n 8 -m "not serial_timing" $F_PE $F_B94 $F_HY
run $WT "changed files, serial lane" -q -rs -m serial_timing $F_PE $F_B94 $F_HY
for i in 1 2 3; do run $WT "4 nodes serial, rep $i (R-TST-157/1)" -v $N331 $NAT $NSB $N27; done
run $WT "static guard + conventions parameters" -v -rs $NG $NC

echo "== B: D9 hold fx_import, fixed x3 then base x2 (e5c-07 .. 11)"
FX=$(mk hold-fixed); BS=$(mk hold-base base_b94)
for i in 1 2 3; do I15_HOLD=fx_import run $FX "D9 fx_import hold, fixed form, rep $i" -v $N27; done
for i in 1 2; do I15_HOLD=fx_import run $BS "D9 fx_import hold, base form (5054743), rep $i" -v $N27; done

echo "== C: D3+D4 on the changed arm (e5c-12 .. 16)"
for i in 1 2 3; do I15_HOLD=fx_bind run $FX "D3+D4 fx_bind hold, fixed form, rep $i" -v $N27; done
run "$(mk m153b m153b)" "R-TST-153 (b) mutant, fixed form" -v $N27
I15_HOLD=fx_bind run "$(mk m152f m152)" "R-TST-152 vacuity: mutant + fx_bind hold, fixed form" -v $N27

echo "== D: never-settling sites of the changed arm (e5c-17 .. 19)"
I15_NEVER="TC-B94-27: the panel mounted lanes base and base_2" run $FX "D9 never settles" -v $N27
I15_NEVER="TC-B94-27: the panel handled the Bind to the same ref" run $FX "D3 never settles" -v $N27
I15_NEVER="TC-B94-27: the panel handled the Bind to variant_b.hex" run $FX "D4 never settles" -v $N27

echo "== E: static guard controls (e5c-20 .. 26)"
run "$(mk g-c2a c2_d6_true)" "guard control C-2: D6 predicate -> lambda: True" -v -rs $NG
run "$(mk g-c2b c2_d7_swap)" "guard control C-2 (b): D7 polls D6's sign" -v -rs $NG
run "$(mk g-c7 c7_wait_for)" "guard control C-7: _wait_for called in TC-B94-27" -v -rs $NG
run "$(mk g-c9 c9_rename_confirm)" "guard control C-9 (163/1): helper _confirm_with not found (no skip)" -v -rs $NG
run "$(mk g-c10 c10_remove_d9)" "guard control C-10: D9 removed (one pause after the import)" -v -rs $NG
run "$(mk g-c2pre base_b94 base_hygiene c2_d6_true)" "pre-corrective guard (5054743) + D6 predicate -> lambda: True" -v -rs $NG
run "$(mk g-c7pre base_b94 base_hygiene c7_wait_for)" "pre-corrective guard (5054743) + _wait_for in TC-B94-27" -v -rs $NG
echo "== done N=$N"
