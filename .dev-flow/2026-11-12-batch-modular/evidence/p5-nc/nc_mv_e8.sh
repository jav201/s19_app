#!/usr/bin/env bash
# TC-MOD-28 mover half (R-MOD.8.4: a method decorated with Textual `on` must stay in S19TuiApp's own body -> mover E8).
# Scratch base commit: `@on(Button.Pressed)` placed on `_land_focus` (a mixin-bound method in the map), replacing the blank line above it.
# The map base is set to the scratch commit (variant none: spans untouched, since the recomputed span excludes the decorator; the other variants shift the span/line and were tried first and ended E2/E3).
# Usage: nc_mv_e8.sh <final-tree>
set -u
D=~/work/zq-mod/p5nc; SC="$D/scratch/mv8"; ST="$D/state"; BASE="$D/base"
TREE="$(realpath "${1:?tree}")"; PY=/data/miniconda3/envs/s19ci/bin/python
E="env -i PATH=/usr/bin:/bin HOME=$ST/zq_iso_user TMPDIR=$ST/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8"
MAP0="$TREE/.dev-flow/2026-11-12-batch-modular/design/module-map.json"
mkdir -p "$SC"; W="$SC/w"; case "$W" in "$SC"/*) rm -rf "$W";; esac
cp -al "$BASE" "$W" && rm -rf "$W/.git" && cp -a "$BASE/.git" "$W/.git"
/usr/bin/python3 -I - "$W" <<'PYEOF'
import os, sys
from pathlib import Path
p = Path(sys.argv[1]) / "s19_app/tui/app.py"
t = p.read_text(encoding="utf-8")
a = "\n\n    def _land_focus(\n"
assert t.count(a) == 1, t.count(a)
os.unlink(p)
p.write_text(t.replace(a, "\n    @on(Button.Pressed)\n    def _land_focus(\n"), encoding="utf-8", newline="\n")
PYEOF
REV=$(cd "$W" && git -c user.name=nc -c user.email=nc@nc commit -q -am "nc28 scratch base" && git rev-parse --short=8 HEAD)
for variant in none span-only span-and-line; do
  /usr/bin/python3 -I - "$MAP0" "$SC/map-$variant.json" "$REV" "$variant" <<'PYEOF'
import json, sys
src, dst, rev, variant = sys.argv[1:5]
m = json.load(open(src, encoding="utf-8"))
m["base"] = rev
e = [x for x in m["app"]["methods"] if x["name"] == "_land_focus"][0]
assert e["module"] == "navigation"
if variant != "none":
    e["span"][0] -= 1
if variant == "span-and-line":
    e["line"] -= 1
json.dump(m, open(dst, "w", encoding="utf-8", newline="\n"), indent=1)
PYEOF
  $E /usr/bin/python3 -I -B "$TREE/tools/modularize/move.py" --repo "$W" --rev "$REV" --map "$SC/map-$variant.json" --py "$PY" > "$SC/o-$variant.out" 2>&1 < /dev/null; rc=$?
  got=$(grep -o "MOVE FAIL [A-Za-z0-9-]*" "$SC/o-$variant.out" | cut -d" " -f3 | sort -u | paste -sd,)
  dirty=$(git -C "$W" status --porcelain | wc -l)
  echo "variant=$variant rc=$rc got=${got:-none} written_files=$dirty"; head -3 "$SC/o-$variant.out" | cut -c1-230
  if [ "$rc" -eq 1 ] && echo ",$got," | grep -q ",E8,"; then echo "TC-MOD-28(mover E8) PASS E8 E8 rc=1 written_files=$dirty ($variant)"; break; fi
done
case "$W" in "$SC"/*) rm -rf "$W";; esac
