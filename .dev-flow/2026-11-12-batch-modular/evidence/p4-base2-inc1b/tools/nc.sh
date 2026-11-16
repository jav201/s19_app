#!/usr/bin/env bash
# Negative controls on scratch copies of the merged tree (HT-09: never in a real worktree).
set -u
S=$HOME/work/zq-base2
cd "$S" || exit 3
REV=$(git -C merged rev-parse HEAD)
for n in nc-guard nc-diag-green nc-diag-red; do rm -rf "$S/$n"; git clone -q merged "$S/$n"; git -C "$S/$n" checkout -q "$REV"; done
# NC-1: drop the R-COPY.26 guard (the two ported lines) -> the teardown test must go RED.
F=s19_app/tui/app/a2l_view.py
python3 - "$S/nc-guard/$F" <<'EOF'
import sys
p = sys.argv[1]
t = open(p, encoding="utf-8").read()
old = "            if not self.is_running:\n                return\n            self._refresh_a2l_filtered_tags(preserve_anchor=False)\n"
assert t.count(old) == 1, t.count(old)
open(p, "w", encoding="utf-8").write(t.replace(old, "            self._refresh_a2l_filtered_tags(preserve_anchor=False)\n"))
EOF
git -C "$S/nc-guard" diff --stat
# NC-2: the diagnostic probe, GREEN as merged, RED with the pre-retarget tuple.
cp "$S/test_zq_nc_diag_seam.py" "$S/nc-diag-green/tests/"
cp "$S/test_zq_nc_diag_seam.py" "$S/nc-diag-red/tests/"
T=tests/test_b103_clipboard_tail.py
python3 - "$S/nc-diag-red/$T" <<'EOF'
import sys
p = sys.argv[1]
t = open(p, encoding="utf-8").read()
old = "for module in (clipboard_module, app_module.deps, capped_module):"
assert t.count(old) == 1, t.count(old)
open(p, "w", encoding="utf-8").write(t.replace(old, "for module in (clipboard_module, app_module, capped_module):"))
EOF
git -C "$S/nc-diag-red" diff --stat
bash "$S/run_t.sh" "$S/nc-guard" "$S/out-nc-guard" 0 600 tests/test_b103_a2l_filter_teardown.py
bash "$S/run_t.sh" "$S/nc-diag-green" "$S/out-nc-diag-green" 0 300 tests/test_zq_nc_diag_seam.py
bash "$S/run_t.sh" "$S/nc-diag-red" "$S/out-nc-diag-red" 0 300 tests/test_zq_nc_diag_seam.py
for o in out-nc-guard out-nc-diag-green out-nc-diag-red; do echo "$o rc=$(cat $S/$o/rc)"; tail -3 "$S/$o/run.txt"; done
echo NC_DONE
