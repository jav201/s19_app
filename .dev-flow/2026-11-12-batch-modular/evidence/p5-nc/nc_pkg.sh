#!/usr/bin/env bash
# TC-MOD-25 (R-MOD.9.3): setuptools discovers both new packages (2/2); without screens_directionb/__init__.py only 1/2.
# Usage: nc_pkg.sh <final-tree>
set -u
D=~/work/zq-mod/p5nc; SC="$D/scratch/pkg"; ST="$D/state"
TREE="$(realpath "${1:?tree}")"; PY=/data/miniconda3/envs/s19ci/bin/python
E="env -i PATH=/usr/bin:/bin HOME=$ST/zq_iso_user TMPDIR=$ST/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8"
mkdir -p "$SC"; W="$SC/w"; case "$W" in "$SC"/*) rm -rf "$W";; esac
cp -al "$TREE" "$W"
CODE='from setuptools import find_packages
r = find_packages(include=["s19_app*"])
want = ["s19_app.tui.app", "s19_app.tui.screens_directionb"]
got = [w for w in want if w in r]
print("FOUND %d/2 %s" % (len(got), ",".join(got)))'
a=$(cd "$W" && $E $PY -I -c "$CODE" < /dev/null); echo "tree:          $a"
rm -f "$W/s19_app/tui/screens_directionb/__init__.py"
b=$(cd "$W" && $E $PY -I -c "$CODE" < /dev/null); echo "no sdb __init__: $b"
if [ "${a%% *}" = "FOUND" ] && echo "$a" | grep -q "^FOUND 2/2" && echo "$b" | grep -q "^FOUND 1/2"; then echo "TC-MOD-25 PASS 2/2 then 1/2"; else echo "TC-MOD-25 FAIL"; fi
case "$W" in "$SC"/*) rm -rf "$W";; esac
