#!/usr/bin/env bash
# Mover negative controls NC-MV-1..10 and the mover cases without an NC number (TC-MOD-30..40), run with the FINAL tree's mover.
# Usage: nc_mv3.sh <final-tree> [case ...]     cases: 0 7 1 2 3 4 5 34 37 6 38 8 9 10   (0 = baseline + TC-40 porcelain, 7 = run twice)
set -u
D=~/work/zq-mod/p5nc; SC="$D/scratch/mv"; ST="$D/state"; BASE="$D/base"; HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$(realpath "${1:?tree}")"; shift
KS="${*:-0 7 1 2 3 4 5 34 37 6 38 8 9 10}"
PY=/data/miniconda3/envs/s19ci/bin/python
MAP0="$TREE/.dev-flow/2026-11-12-batch-modular/design/module-map.json"
TOOLS="$TREE/tools/modularize"
E="env -i PATH=/usr/bin:/bin HOME=$ST/zq_iso_user TMPDIR=$ST/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8"
mkdir -p "$SC"

mk() {  # mk <dir>: fresh work copy of the base checkout (files hard-linked, .git copied)
  case "$1" in "$SC"/*) rm -rf "$1";; *) echo "bad dir $1"; exit 2;; esac
  cp -al "$BASE" "$1" && rm -rf "$1/.git" && cp -a "$BASE/.git" "$1/.git"
}
mover() {  # mover <work> <map> <rev> <tooldir> <out>  -> prints rc
  $E /usr/bin/python3 -I -B "$4/move.py" --repo "$1" --rev "$3" --map "$2" --py "$PY" > "$5" 2>&1 < /dev/null; echo $?
}
porcelain() { git -C "$1" status --porcelain | sort; }
report() {  # report <id> <expected-regex-on-FAIL-code> <work> <out> <rc>
  local id=$1 exp=$2 w=$3 out=$4 rc=$5 got dirty
  got=$(grep -o "MOVE FAIL [A-Za-z0-9-]*" "$out" | cut -d" " -f3 | sort -u | paste -sd,)
  dirty=$(porcelain "$w" | wc -l)
  if [ "$rc" -eq 1 ] && echo ",$got," | grep -qE ",($exp),"; then r=PASS; else r=FAIL; fi
  echo "$id $r $exp ${got:-none} rc=$rc written_files=$dirty"
  grep "^MOVE FAIL" "$out" | head -2 | cut -c1-230
}
sums() { (cd "$1" && find s19_app/tui/app s19_app/tui/screens_directionb .modularize -type f -name '*.*' ! -name '*.pyc' | sort | xargs sha256sum); }

for k in $KS; do
  W="$SC/w$k"; mk "$W"; O="$SC/o$k.out"; MAP="$MAP0"; REV=4f721985; TL="$TOOLS"
  case "$k" in
  0)
    rc=$(mover "$W" "$MAP" $REV "$TL" "$O"); cat "$O" | cut -c1-230
    pc=$(porcelain "$W"); want=$(printf ' D s19_app/tui/app.py\n D s19_app/tui/screens_directionb.py\n?? .modularize/\n?? s19_app/tui/app/\n?? s19_app/tui/screens_directionb/\n' | sort)
    echo "--- git status --porcelain"; echo "$pc"
    if [ "$rc" -eq 0 ] && [ "$pc" = "$want" ] && grep -q "^MOVE OK" "$O"; then echo "TC-MOD-40 PASS porcelain=2 deletions + 2 package dirs + .modularize/ only; MOVE OK rc=0"; else echo "TC-MOD-40 FAIL rc=$rc"; fi
    sums "$W" > "$SC/sums0.txt"; echo "files_hashed=$(wc -l < "$SC/sums0.txt") digest=$(sha256sum < "$SC/sums0.txt" | cut -c1-16)";;
  7)
    W2="$SC/w7b"; mk "$W2"; rc1=$(mover "$W" "$MAP" $REV "$TL" "$O"); rc2=$(mover "$W2" "$MAP" $REV "$TL" "$SC/o7b.out")
    sums "$W" > "$SC/s7a.txt"; sums "$W2" > "$SC/s7b.txt"; n=$(wc -l < "$SC/s7a.txt")
    if [ "$rc1" -eq 0 ] && [ "$rc2" -eq 0 ] && cmp -s "$SC/s7a.txt" "$SC/s7b.txt" && [ "$n" -gt 30 ]; then r=PASS; else r=FAIL; fi
    echo "NC-MV-7 $r identical-sha256-per-file equal files=$n rc=$rc1,$rc2 digest=$(sha256sum < "$SC/s7a.txt" | cut -c1-16)/$(sha256sum < "$SC/s7b.txt" | cut -c1-16)"
    rm -rf "$W2";;
  1|2|3|4|5|34|37)
    MAP="$SC/map$k.json"; /usr/bin/python3 -I "$HERE/mv_mapmut.py" "$MAP0" "$MAP" "$k" > "$SC/mut$k.txt" 2>&1 || { echo "NC-MV-$k FAIL mutation-error $(tail -c 200 "$SC/mut$k.txt")"; rm -rf "$W"; continue; }
    rc=$(mover "$W" "$MAP" $REV "$TL" "$O")
    case "$k" in
      1) report NC-MV-1 E3 "$W" "$O" "$rc";; 2) report NC-MV-2 E4 "$W" "$O" "$rc";; 3) report NC-MV-3 E9 "$W" "$O" "$rc";;
      4) report NC-MV-4 E11 "$W" "$O" "$rc";; 5) report NC-MV-5 E1 "$W" "$O" "$rc";;
      34) report "TC-34(../x)" E5 "$W" "$O" "$rc";;
      37) report "TC-37(on_button_pressed->mixin)" "E[0-9]+" "$W" "$O" "$rc";;
    esac; cat "$SC/mut$k.txt" | cut -c1-160;;
  6|38)
    REV=$(cd "$W" && /usr/bin/python3 -I "$HERE/mv_basemut.py" "$W" "$k" > /dev/null && git -c user.name=nc -c user.email=nc@nc commit -q -am "nc$k scratch base" && git rev-parse --short=8 HEAD)
    [ -n "$REV" ] || { echo "NC-MV-$k FAIL scratch-base-error"; rm -rf "$W"; continue; }
    MAP="$SC/map$k.json"; /usr/bin/python3 -I "$HERE/mv_mapmut.py" "$MAP0" "$MAP" "base:$REV" > /dev/null
    rc=$(mover "$W" "$MAP" $REV "$TL" "$O")
    if [ "$k" = 6 ]; then report "NC-MV-6" E12 "$W" "$O" "$rc"; else report "TC-38(local os)" E6 "$W" "$O" "$rc"; fi;;
  8|9|10)
    T="$SC/tool$k"; rm -rf "$T"; cp -r "$TOOLS" "$T"; rm -rf "$T/__pycache__"
    /usr/bin/python3 -I "$HERE/mv_toolmut.py" "$T/move_emit.py" "$k" || { echo "NC-MV-$k FAIL tool-mutation-error"; rm -rf "$W"; continue; }
    rc=$(mover "$W" "$MAP" $REV "$T" "$O")
    if [ "$k" = 8 ]; then
      if [ "$rc" -eq 1 ] && grep -q "^MOVE FAIL" "$O" && (grep -q "MOVE FAIL \(cycle\|direction\|fresh import\)" "$O"); then r=PASS; else r=FAIL; fi
      echo "NC-MV-8 $r MOVE-FAIL(fresh-import|cycle) $(grep -o 'MOVE FAIL [a-z ]*' "$O" | sort -u | paste -sd,) rc=$rc"; grep -E "^MOVE (imports_fresh|FAIL cycle|FAIL direction)" "$O" | head -3 | cut -c1-200
    elif [ "$k" = 9 ]; then
      if [ "$rc" -eq 1 ] && grep -q "^MOVE FAIL deps-bound" "$O"; then r=PASS; else r=FAIL; fi
      echo "NC-MV-9 $r MOVE-FAIL(deps-bound) $(grep -o 'MOVE FAIL [a-z-]*' "$O" | sort -u | paste -sd,) rc=$rc"; grep -E "^SELF|^MOVE FAIL deps-bound" "$O" | head -4 | cut -c1-200
    else
      echo "NC-MV-10 mover rc=$rc: $(tail -1 "$O")"; grep -E "^SELF" "$O" | head -2
      mk "$SC/w0b"; $E /usr/bin/python3 -I -B "$TOOLS/move.py" --repo "$SC/w0b" --rev $REV --map "$MAP" --py "$PY" > "$SC/o0b.out" 2>&1 < /dev/null
      echo "baseline-mover rc=$? $(tail -1 "$SC/o0b.out")"
      echo "--- diff -rq baseline vs mutated (generated packages)"; diff -rq "$SC/w0b/s19_app/tui/app" "$W/s19_app/tui/app"; diff -rq "$SC/w0b/s19_app/tui/screens_directionb" "$W/s19_app/tui/screens_directionb"
      echo "--- diff (first 20 lines)"; diff -r "$SC/w0b/s19_app/tui" "$W/s19_app/tui" | head -20
      echo "--- verifier on the mutated output"; $E /usr/bin/python3 -I -B "$TOOLS/verify.py" --repo "$W" --base-rev 4f721985 --map "$MAP" --py "$PY" --state "$ST" 2>&1 < /dev/null | grep -E "^VERIFY (FAIL|OK)" | head -4 | cut -c1-220
      rm -rf "$SC/w0b"
    fi; rm -rf "$T";;
  esac
  rm -rf "$W"
done
