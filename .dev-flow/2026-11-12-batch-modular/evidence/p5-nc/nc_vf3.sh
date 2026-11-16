#!/usr/bin/env bash
# NC-VF-1..25 on the FINAL tree.  Usage: nc_vf3.sh <tree> [k ...]   (k=0: unmutated baseline)
# 1..16 = nc_mut2.py (p0-fix, unchanged); 17..25 = nc_mut3.py (cases without an NC-VF number).
set -u
D=~/work/zq-mod/p5nc; SC="$D/scratch/vf"; ST="$D/state"; HERE="$(cd "$(dirname "$0")" && pwd)"
TREE="$(realpath "${1:?tree}")"; shift
KS="${*:-0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25}"
PY=/data/miniconda3/envs/s19ci/bin/python
MAP0="$TREE/.dev-flow/2026-11-12-batch-modular/design/module-map.json"
declare -A EXP=( [1]=V1 [2]=V2+V10 [3]=V4 [4]=V5 [5]=V6+V7 [6]=V8 [7]=V9 [8]=V11 [9]="V13|V14" [10]=V4+V16 [11]=V12 [12]=V17 [13]="V4|V5" [14]=V18 [15]=V18 [16]=V19
  [17]=V3 [18]=V10 [19]=V11 [20]=V11 [21]=V14 [22]=V15 [23]="V12|V13" [24]=V8 [25]=V9 )
declare -A NAME=( [1]="S19TuiApp._land_focus" [3]="_busy_tick" [14]="deps.Label" [17]="_helper" [24]="_is_link_stat" )
mkdir -p "$SC"
E="env -i PATH=/usr/bin:/bin HOME=$ST/zq_iso_user TMPDIR=$ST/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8"
for k in $KS; do
  W="$SC/nc$k"; case "$W" in "$SC"/nc*) rm -rf "$W";; *) echo bad; exit 2;; esac
  cp -al "$TREE" "$W"; MAP="$MAP0"; msg=""
  if [ "$k" -gt 0 ]; then
    if [ "$k" -le 16 ]; then script="$HERE/nc_mut2.py"; else script="$HERE/nc_mut3.py"; fi
    if ! msg=$(/usr/bin/python3 -I "$script" "$W" $k "$SC" 2>&1); then echo "NC-VF-$k FAIL ${EXP[$k]} mutation-error: $(echo $msg | tail -c 150)"; rm -rf "$W"; continue; fi
    case "$msg" in *MAP=*) MAP=$(echo "$msg" | sed -n 's/.*MAP=\([^ ]*\).*/\1/p');; esac
  fi
  OUT="$SC/nc$k.out"
  $E /usr/bin/python3 -I -B "$W/tools/modularize/verify.py" --repo "$W" --base-rev 4f721985 --map "$MAP" --py "$PY" --state "$ST" > "$OUT" 2>&1 < /dev/null; rc=$?
  if [ "$k" -eq 0 ]; then
    grep -E "^VERIFY" "$OUT" | cut -c1-260
    if [ $rc -eq 0 ] && grep -q "^VERIFY OK" "$OUT"; then echo "NC-VF-0 PASS baseline VERIFY OK rc=0"; else echo "NC-VF-0 FAIL baseline VERIFY OK rc=$rc"; fi
    rm -rf "$W"; continue
  fi
  got=$(grep -o "^VERIFY FAIL V[0-9]*" "$OUT" | cut -d" " -f3 | sort -u | paste -sd,)
  exp="${EXP[$k]}"; ok=0
  if [[ "$exp" == *+* ]]; then ok=1; IFS=+ read -ra need <<< "$exp"; for v in "${need[@]}"; do grep -q "^VERIFY FAIL $v:" "$OUT" || ok=0; done
  else IFS="|" read -ra any <<< "$exp"; for v in "${any[@]}"; do grep -q "^VERIFY FAIL $v:" "$OUT" && ok=1; done; fi
  nm="${NAME[$k]:-}"; [ $k -eq 15 ] && nm=$(echo "$msg" | sed -n 's/.*TARGET=\([^ ]*\).*/\1/p')
  [ -n "$nm" ] && { grep -q "^VERIFY FAIL ${exp%%[+|]*}:.*$nm" "$OUT" || ok=0; }
  [ $rc -eq 1 ] || ok=0
  if [ $ok -eq 1 ]; then r=PASS; else r=FAIL; fi
  echo "NC-VF-$k $r $exp ${got:-none} rc=$rc $msg" | cut -c1-220
  grep "^VERIFY FAIL" "$OUT" | grep -E "^VERIFY FAIL (${exp//[+|]/|}):" | head -2 | cut -c1-240
  grep -E "caps_over=[1-9]" "$OUT" | cut -c1-300
  rm -rf "$W"
done
