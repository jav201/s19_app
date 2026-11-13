#!/usr/bin/env bash
# TC-MOD-52: retargeter acceptance 2 (undo the recorded edits -> identical text) on the final tree's retargeter.
#  A. real run on the pre-retarget tests (62b6e712) over the final product: tool exits 0 (its in-memory acceptance 2 passed) and an
#     independent undo check shows 0 differing lines outside the inserted `.deps` spans.
#  B. control: a scratch copy of the tool whose apply_edits also appends one stray space -> must stop with `diff-outside-spans`, writing nothing.
# Usage: nc_rt3.sh <final-tree>
set -u
D=~/work/zq-mod/p5nc; SC="$D/scratch/rt"; ST="$D/state"; HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$(realpath "${1:?tree}")"
E="env -i PATH=/usr/bin:/bin HOME=$ST/zq_iso_user TMPDIR=$ST/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8"
M=.dev-flow/2026-11-12-batch-modular/design/module-map.json; R=.dev-flow/2026-11-12-batch-modular/design/retarget-accepted-refusals.txt
mkdir -p "$SC"
mk() { case "$1" in "$SC"/*) rm -rf "$1";; *) echo bad; exit 2;; esac; cp -al "$TREE" "$1" && rm -rf "$1/.git" && cp -a "$TREE/.git" "$1/.git" && (cd "$1" && git checkout -q 62b6e712 -- tests); }

W="$SC/a"; mk "$W"
$E /usr/bin/python3 -I -B "$W/tools/modularize/retarget_tests.py" --repo "$W" --map "$W/$M" --accept-refusal "$W/$R" > "$SC/a.out" 2>&1 < /dev/null; rc=$?
grep -E "^RETARGET (files_scanned|CHECK|OK)" "$SC/a.out" | cut -c1-200; echo "retarget_rc=$rc"
$E /usr/bin/python3 -I -B "$HERE/rt_undo_check.py" "$W" 62b6e712 > "$SC/a-undo.out" 2>&1 < /dev/null; urc=$?; tail -3 "$SC/a-undo.out" | cut -c1-200
if [ $rc -eq 0 ] && [ $urc -eq 0 ] && grep -q "lines_outside_spans=0" "$SC/a-undo.out" && grep -q "^RETARGET OK" "$SC/a.out"; then echo "TC-MOD-52 PASS 0-lines-outside-spans retarget rc=0 undo-check rc=0"; else echo "TC-MOD-52 FAIL retarget_rc=$rc undo_rc=$urc"; fi
rm -rf "$W"

W="$SC/b"; mk "$W"; T="$SC/toolb"; rm -rf "$T"; cp -r "$TREE/tools/modularize" "$T"; rm -rf "$T/__pycache__"
/usr/bin/python3 -I - "$T/retarget_scan.py" <<'PYEOF' || { echo "TC-MOD-52-NC FAIL tool-mutation-error"; exit 1; }
import os, sys
from pathlib import Path
p = Path(sys.argv[1]); t = p.read_text(encoding="utf-8")
a = '    parts.append(text[pos:])\n    return "".join(parts), placements\n'
assert t.count(a) == 1
os.unlink(p); p.write_text(t.replace(a, '    parts.append(text[pos:] + " ")\n    return "".join(parts), placements\n'), encoding="utf-8", newline="\n")
PYEOF
$E /usr/bin/python3 -I -B "$T/retarget_tests.py" --repo "$W" --map "$W/$M" --accept-refusal "$W/$R" > "$SC/b.out" 2>&1 < /dev/null; rc=$?
dirty=$(git -C "$W" diff --name-only | wc -l)  # unstaged = written by the tool (the staged tests checkout is the setup)
tail -2 "$SC/b.out" | cut -c1-200
if [ $rc -ne 0 ] && grep -q "diff-outside-spans" "$SC/b.out" && [ "$dirty" -eq 0 ]; then echo "TC-MOD-52-NC PASS stops with diff-outside-spans rc=$rc files_written=$dirty"; else echo "TC-MOD-52-NC FAIL rc=$rc files_written=$dirty"; fi
rm -rf "$W" "$T"
