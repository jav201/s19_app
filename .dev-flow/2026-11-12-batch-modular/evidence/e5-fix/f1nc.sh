#!/usr/bin/env bash
# E5 F1: fixed laws GREEN on tree; mutants RED with fixed tests, GREEN with pre-fix tests (shows the gap).
set -u
Z=~/work/zq-mod; R=$Z/f1nc; PY=$HOME/miniconda3/envs/s19ci/bin/python; rm -rf $R; mkdir -p $R/st/zq_iso_user $R/st/tmp
git clone -q /tmp/zq-f1.bundle $R/t 2>/dev/null; cd $R/t && git checkout -q bd63404b || { echo CHECKOUT_FAIL; exit 3; }
E="env -i PATH=/usr/bin:/bin HOME=$R/st/zq_iso_user TMPDIR=$R/st/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8 TERM=xterm-256color"
N1="tests/test_b99_staging.py::test_tc_b99_13_census_sees_primitives_called_through_deps"
N2="tests/test_b99_staging.py::test_tc_b99_13_no_final_name_replace_outside_placement"
N3="tests/test_tui_directionb.py::test_tc_042_8_strip_colour_is_pure_reuse_of_batch27_helpers"
run() { r=$(cd $R/t && $E $PY -m pytest -q -p no:cacheprovider "$@" < /dev/null 2>&1 | tail -1); echo "$r"; }
echo "GREEN fixed tree: $(run $N1 $N2 $N3)"
printf '\n\ndef _nc_f1_unlisted(a, b):\n    deps.os.replace(a, b)\n' >> s19_app/tui/app/save_commit.py
sed -i 's/^    def update_memory_strip(self) -> None:$/    def update_memory_strip(self) -> None:\n        if False: deps.parse_a2l_file(None)/' s19_app/tui/app/workspace_view.py
git diff --stat | tail -1
echo "NC-F1-a fixed staging law on mutant (expect failed): $(run $N2)"
echo "NC-F1-b fixed strip law on mutant (expect failed): $(run $N3)"
git checkout -q bd63404b~1 -- tests/test_b99_staging.py tests/test_tui_directionb.py
echo "pre-fix staging law on mutant (gap: passed): $(run $N2)"
echo "pre-fix strip law on mutant (gap: passed): $(run $N3)"
cd /; rm -rf $R; echo F1NC_DONE
