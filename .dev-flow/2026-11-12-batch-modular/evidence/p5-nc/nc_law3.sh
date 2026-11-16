#!/usr/bin/env bash
# H-13 laws (TC-MOD-7L): each law's test is GREEN on the final tree and RED under the law's own mutant.
# Usage: nc_law3.sh <final-tree> [row ...]
set -u
D=~/work/zq-mod/p5nc; SC="$D/scratch/law"; ST="$D/state"; HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$(realpath "${1:?tree}")"; shift
PY=/data/miniconda3/envs/s19ci/bin/python
E="env -i PATH=/usr/bin:/bin HOME=$ST/zq_iso_user TMPDIR=$ST/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8"
declare -A NODE=(
 [1]="tests/test_b100_a2l_progress.py::test_tc_b100_73_one_argument_callers_outside_the_app_are_unchanged"
 [10]="tests/test_b100_reuse.py::test_tc_b100_57_export_holds_no_byte_identity_rule"
 [15]="tests/test_b100_session_reset.py::test_tc_b100_08_call_site_census"
 [20]="tests/test_b100_load_question.py::test_tc_b100_44_no_private_dirty_read_outside_the_panel"
 [32]="tests/test_b99_staging.py::test_tc_b99_13_no_final_name_replace_outside_placement"
 [33]="tests/test_b103_copy_quit_dialog.py::test_r_dlg_14_101_copy_quit_has_reachable_shared_opener"
 [39]="tests/test_universal_paste.py::test_ac1_no_tui_module_constructs_a_stock_input"
 [43]="tests/test_b101_doc_hygiene.py::test_r_doc_dev_11_1_overview_names_every_window"
 [44]="tests/test_b101_doc_hygiene.py::test_r_doc_ref_1_1_named_paths_exist"
 [69]="tests/test_tui_patch_history_strip.py::test_tc081_4_no_binding_diff"
 [74]="tests/test_import_census.py::test_tc653_safe_text_import_census"
 [75]="tests/test_render_hexview.py::test_tc651_import_census_all_consumers_read_render_hexview"
 [76]="tests/test_render_hexview.py::test_tc652_wrapper_absence_and_renderer_surface" )
ROWS="${*:-1 10 15 20 32 33 39 43 44 69 74 75 76}"
mkdir -p "$SC"
mk() { case "$1" in "$SC"/*) rm -rf "$1";; *) echo bad; exit 2;; esac; cp -al "$TREE" "$1" && rm -rf "$1/.git" && cp -a "$TREE/.git" "$1/.git"; }
runt() {  # runt <work> <node> <out>
  (cd "$1" && timeout 900 $E $PY -m pytest -q -p no:cacheprovider -o addopts= "$2" > "$3" 2>&1 < /dev/null); echo $?
}
for row in $ROWS; do
  node="${NODE[$row]}"
  W="$SC/g$row"; mk "$W"
  rcg=$(runt "$W" "$node" "$SC/g$row.out"); sg=$(tail -1 "$SC/g$row.out" | cut -c1-120)
  rm -rf "$W"; W="$SC/m$row"; mk "$W"
  mout=$(/usr/bin/python3 -I "$HERE/nc_law_mut.py" "$W" "$row" 2>&1) || { echo "7L-$row FAIL mutation-error $(echo $mout | tail -c 160)"; rm -rf "$W"; continue; }
  rcm=$(runt "$W" "$node" "$SC/m$row.out"); sm=$(tail -1 "$SC/m$row.out" | cut -c1-120)
  if [ "$rcg" -eq 0 ] && [ "$rcm" -eq 1 ]; then r=PASS; else r=FAIL; fi
  echo "7L-$row $r GREEN-on-tree+RED-under-mutant tree_rc=$rcg mutant_rc=$rcm | tree: $sg | mutant: $sm"
  echo "    node: ${node#tests/}"
  grep -E "^E  +(Assertion|assert)|^E  +[A-Za-z]+Error" "$SC/m$row.out" | head -2 | cut -c1-230 | sed 's/^/    /'
  rm -rf "$W"
done
