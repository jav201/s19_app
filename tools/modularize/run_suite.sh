#!/usr/bin/env bash
# Full-suite run for the modularization equivalence check (before/after).
# Usage: run_suite.sh <bundle> <rev> <out_dir> [workers]
# Writes <out_dir>/junit.xml, <out_dir>/suite.txt, <out_dir>/outcomes.tsv (nodeid<TAB>outcome), <out_dir>/rc (pytest exit code).
# Stale results of an earlier run are deleted first, so a run that dies before writing junit leaves no outcomes.tsv.
set -u
BUNDLE="$1"; REV="$2"; OUT="$3"; NW="${4:-8}"
PY="$HOME/miniconda3/envs/s19ci/bin/python"
[ -x "$PY" ] || PY="/data/miniconda3/envs/s19ci/bin/python"
mkdir -p "$OUT"; TREE="$OUT/tree"; ST="$OUT/state"
rm -rf "$TREE" "$ST"
rm -f "$OUT/junit.xml" "$OUT/outcomes.tsv" "$OUT/rc" "$OUT/suite.txt"
git clone -q "$BUNDLE" "$TREE" 2>/dev/null; git -C "$TREE" checkout -q "$REV" || { echo "CHECKOUT_FAIL"; exit 3; }
mkdir -p "$ST/zq_iso_user" "$ST/xdg" "$ST/tmp"
cd "$TREE" || exit 3
env -i PATH="/usr/bin:/bin" HOME="$ST/zq_iso_user" XDG_CONFIG_HOME="$ST/xdg/c" XDG_DATA_HOME="$ST/xdg/d" \
  XDG_CACHE_HOME="$ST/xdg/k" XDG_STATE_HOME="$ST/xdg/s" TMPDIR="$ST/tmp" PYTHONDONTWRITEBYTECODE=1 \
  PYTHONIOENCODING=utf-8 LANG=C.UTF-8 TERM=xterm-256color \
  "$PY" -c "import sys; sys.path.insert(0,'.'); import s19_app; print(s19_app.__file__); import pytest; sys.exit(pytest.main(['-q','-p','no:cacheprovider','-n','$NW','--dist','loadfile','--junitxml','$OUT/junit.xml','-rfE','tests']))" \
  < /dev/null > "$OUT/suite.txt" 2>&1
RC=$?
echo "$RC" > "$OUT/rc"
"$PY" - "$OUT/junit.xml" "$OUT/outcomes.tsv" <<'EOF'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
rows = []
for tc in root.iter("testcase"):
    cls = tc.get("classname", ""); name = tc.get("name", "")
    path = cls.replace(".", "/") + ".py" if cls else ""
    out = "passed"
    for tag in ("failure", "error", "skipped"):
        if tc.find(tag) is not None:
            out = {"failure": "failed", "error": "error", "skipped": "skipped"}[tag]
    rows.append(f"{path}::{name}\t{out}")
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(sorted(rows)) + "\n")
from collections import Counter
print(dict(Counter(r.split("\t")[1] for r in rows)))
EOF
tail -3 "$OUT/suite.txt"
echo "SUITE_DONE rc=$RC"
