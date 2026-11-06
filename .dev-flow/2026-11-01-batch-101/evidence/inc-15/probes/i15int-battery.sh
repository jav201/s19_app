#!/usr/bin/env bash
# usage: i15int-battery.sh  (LAN Linux host; the worktree ~/work/s19_i15int is never mutated)
set -u
S=/tmp/i15int/scripts
R=$S/i15int-run.sh
WT=$HOME/work/s19_i15int
PY=/data/miniconda3/envs/s19ci/bin/python
export I15INT_COMMIT="77f4553 (c2cba35 + the Inc 15 tests/docs patch, sha256 fdde60cc)"
F_PE=tests/test_tui_patch_editor_v2.py
F_B94=tests/test_tui_flow_execution_b94.py
F_HY=tests/test_suite_hygiene.py
N331=$F_PE::test_tc331_disable_guard_predicate_tracks_source_path
NAT=$F_PE::test_at030c_directly_dropped_file_is_listed_and_loadable
NSB=$F_PE::test_save_back_prompt
N27=$F_B94::test_tc_b94_27_lane_binding_isolation_and_noop
NG=$F_HY::test_r_tst_154_155_inc15_arms_wait_through_settled
N=0
run() { N=$((N + 1)); $R "$1" "int-$(printf %02d $N)" "$2" "${@:3}"; }

copy() { # dir : fresh copy of the worktree (fixed form), no .git
  rm -rf "$1"; mkdir -p "$1"
  rsync -a --exclude .git --exclude __pycache__ "$WT/" "$1/"
}
mk() { # name [mutants...] : fixed-form copy
  local d=/tmp/i15int/trees/$1; shift
  copy "$d"; [ $# -gt 0 ] && $PY $S/i15int_mutate.py "$d" "$@" >&2
  echo "$d"
}
mkbase() { # name [mutants...] : base-form copy (the changed tests + doc as at c2cba35)
  local d=/tmp/i15int/trees/$1; shift
  copy "$d"
  for f in $F_PE $F_B94 $F_HY docs/engineering-rules.md; do git -C "$WT" show HEAD:$f > "$d/$f"; done
  [ $# -gt 0 ] && $PY $S/i15int_mutate.py "$d" "$@" >&2
  echo "$d"
}

echo "== A: GREEN in the worktree (int-01 .. int-05)"
run $WT "changed files, parallel lane -n 6" -q -rs -n 6 -m "not serial_timing" $F_PE $F_B94 $F_HY
run $WT "changed files, serial lane" -q -rs -m serial_timing $F_PE $F_B94 $F_HY
for i in 1 2 3; do run $WT "4 nodes serial, rep $i (R-TST-157)" -v $N331 $NAT $NSB $N27; done

echo "== B: holds, fixed x3 then base x2 (int-06 .. int-40)"
FX=$(mk hold-fixed); BS=$(mkbase hold-base)
hold() { # tag mode action node
  for i in 1 2 3; do I15_HOLD=$2 I15_HOLD_ACTION=$3 run $FX "$1 hold, fixed form, rep $i" -v $4; done
  for i in 1 2; do I15_HOLD=$2 I15_HOLD_ACTION=$3 run $BS "$1 hold, base form, rep $i" -v $4; done
}
hold "D1 patch_action[*]" patch_action "" $N331
hold "D2 patch_action[parse_paste]" patch_action parse_paste $N331
hold "D3+D4 fx_bind" fx_bind "" $N27
hold "D5 change_file" change_file "" $NAT
hold "D6 patch_action[apply_doc]" patch_action apply_doc $NSB
hold "D7 save_back[decline]" save_back decline $NSB
hold "D8 save_back[confirm]" save_back confirm $NSB

echo "== C: product mutants (int-41 .. int-49)"
run "$(mk m150b m150b)" "R-TST-150 (b) mutant, fixed form" -v $N331
run "$(mk m151b m151b)" "R-TST-151 (b) mutant, fixed form" -v $N331
run "$(mk m153b m153b)" "R-TST-153 (b) mutant, fixed form" -v $N27
I15_HOLD=fx_bind run "$(mk m152f m152)" "R-TST-152 vacuity: mutant + fx_bind hold, fixed form" -v $N27
I15_HOLD=fx_bind run "$(mkbase m152b m152)" "R-TST-152 vacuity: mutant + fx_bind hold, base form" -v $N27
I15_HOLD=save_back I15_HOLD_ACTION=decline run "$(mk m161f m161b)" "R-TST-161 (b): mutant + decline hold, fixed form" -v $NSB
I15_HOLD=save_back I15_HOLD_ACTION=decline run "$(mkbase m161bb m161b)" "R-TST-161 (b): mutant + decline hold, base form" -v $NSB
I15_HOLD=save_back I15_HOLD_ACTION=confirm run "$(mk m162f m162b)" "R-TST-162 (b): mutant + confirm hold, fixed form" -v $NSB
I15_HOLD=save_back I15_HOLD_ACTION=confirm run "$(mkbase m162bb m162b)" "R-TST-162 (b): mutant + confirm hold, base form" -v $NSB

echo "== D: R-TST-154 behavioural, one never-settling site per run (int-50 .. int-57)"
NV=$(mk never)
I15_NEVER="TC-331: the load of f.json reached the change document" run $NV "D1 never settles" -v $N331
I15_NEVER="TC-331: the parsed paste reached the change document" run $NV "D2 never settles" -v $N331
I15_NEVER="TC-B94-27: the panel handled the Bind to the same ref" run $NV "D3 never settles" -v $N27
I15_NEVER="TC-B94-27: the panel handled the Bind to variant_b.hex" run $NV "D4 never settles" -v $N27
I15_NEVER="AT-030c: the load of dropped.json reached the change document" run $NV "D5 never settles" -v $NAT
I15_NEVER="TC-051: the apply showed the save-back prompt" run $NV "D6 never settles" -v $NSB
I15_NEVER="TC-051: the decline hid the save-back prompt" run $NV "D7 never settles" -v $NSB
I15_NEVER="TC-051: the confirm hid the save-back prompt" run $NV "D8 never settles" -v $NSB

echo "== E: static guard negative controls (int-58 .. int-64)"
run "$(mk g1 g_remove_d1)" "guard control: wait D1 removed" -v $NG
run "$(mk g2 g_move_d1)" "guard control: wait D1 moved after its read (R-TST-163/2)" -v $NG
run "$(mk g3 g_fstring_d3)" "guard control: D3 description built as an f-string" -v $NG
run "$(mk g4 g_desc_d5)" "guard control: D5 description changed" -v $NG
run "$(mk g5 g_range_loop)" "guard control: range-counted pause loop in TC-331" -v $NG
run "$(mk g6 g_local_settled)" "guard control: module-local settled in the b94 module (integrator's guard)" -v $NG
G7=$(mk g7 g_local_settled)
$PY - "$G7/$F_HY" <<'EOF'
import sys
p = sys.argv[1]
t = open(p, encoding="utf-8", newline="").read()
start = t.index("    # R-TST-155: the name ``settled`` the sites call is the shared wait.")
end = t.index("    for module_rel, arm_name, helper, trigger, description in _INC15_WAIT_SITES:")
open(p, "w", encoding="utf-8", newline="").write(t[:start] + t[end:])
print("i15int: binding check stripped (pre-integration guard)", file=sys.stderr)
EOF
run "$G7" "guard control: module-local settled, pre-integration guard (68452f6 form)" -v $NG
echo "== done N=$N"
