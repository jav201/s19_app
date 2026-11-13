#!/usr/bin/env bash
# TC-MOD-37 chain: `on_button_pressed` mapped to a mixin.  Mover half (spec: refused) and verifier half (spec: V9 if forced).
# Usage: nc_mv37.sh <final-tree>
set -u
D=~/work/zq-mod/p5nc; SC="$D/scratch/mv37"; ST="$D/state"; BASE="$D/base"; HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$(realpath "${1:?tree}")"; PY=/data/miniconda3/envs/s19ci/bin/python
E="env -i PATH=/usr/bin:/bin HOME=$ST/zq_iso_user TMPDIR=$ST/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8"
MAP0="$TREE/.dev-flow/2026-11-12-batch-modular/design/module-map.json"
mkdir -p "$SC"; W="$SC/w"; case "$W" in "$SC"/*) rm -rf "$W";; esac
cp -al "$BASE" "$W" && rm -rf "$W/.git" && cp -a "$BASE/.git" "$W/.git"
/usr/bin/python3 -I "$HERE/mv_mapmut.py" "$MAP0" "$SC/map.json" 37
$E /usr/bin/python3 -I -B "$TREE/tools/modularize/move.py" --repo "$W" --rev 4f721985 --map "$SC/map.json" --py "$PY" > "$SC/mover.out" 2>&1 < /dev/null; rc=$?
echo "mover rc=$rc: $(tail -1 "$SC/mover.out")"
if [ $rc -eq 0 ]; then
  echo "TC-MOD-37(mover) FAIL expected-refused got MOVE OK rc=0 (the mover has no error code for a moved core-pinned handler)"
  $E /usr/bin/python3 -I -B "$TREE/tools/modularize/verify.py" --repo "$W" --base-rev 4f721985 --map "$SC/map.json" --py "$PY" --state "$ST" > "$SC/verify.out" 2>&1 < /dev/null; vrc=$?
  grep "^VERIFY FAIL V9" "$SC/verify.out" | head -2 | cut -c1-240
  if [ $vrc -eq 1 ] && grep -q "^VERIFY FAIL V9" "$SC/verify.out"; then echo "TC-MOD-37(verifier) PASS V9 $(grep -o '^VERIFY FAIL V[0-9]*' "$SC/verify.out" | cut -d' ' -f3 | sort -u | paste -sd,) rc=1"; else echo "TC-MOD-37(verifier) FAIL rc=$vrc"; fi
else
  echo "TC-MOD-37(mover) PASS refused rc=$rc"
fi
case "$W" in "$SC"/*) rm -rf "$W";; esac
