#!/usr/bin/env bash
# NC-VF-1..16.  Usage: nc_vf2.sh <moved-tree> [k ...]
set -u
D=~/work/zq-mod/vffix; SC="$D/scratch/nc"; ST="$D/state"
TREE="$(realpath "${1:?tree}")"; shift
KS="${*:-1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16}"
PY=/data/miniconda3/envs/s19ci/bin/python
MAP="$D/tree/.dev-flow/2026-11-12-batch-modular/design/module-map.json"
VERIFY="$D/tree/tools/modularize/verify.py"
declare -A EXP=( [1]=V1 [2]=V2+V10 [3]=V4 [4]=V5 [5]=V6+V7 [6]=V8 [7]=V9 [8]=V11 [9]="V13|V14" [10]=V4+V16 [11]=V12 [12]=V17 [13]="V4|V5" [14]=V18 [15]=V18 [16]=V19 )
declare -A NAME=( [1]="S19TuiApp._land_focus" [3]="_busy_tick" [14]="deps.Label" )
mkdir -p "$SC"
for k in $KS; do
  W="$SC/nc$k"; case "$W" in "$SC"/nc*) rm -rf "$W";; *) echo bad; exit 2;; esac
  cp -al "$TREE" "$W"
  if ! msg=$(/usr/bin/python3 -I "$SC/nc_mut2.py" "$W" $k 2>&1); then echo "NC-VF-$k FAIL ${EXP[$k]} mutation-error: $(echo $msg | tail -c 150)"; rm -rf "$W"; continue; fi
  OUT="$SC/nc$k.out"
  /usr/bin/python3 -I "$VERIFY" --repo "$W" --base-rev 4f721985 --map "$MAP" --py "$PY" --state "$ST" > "$OUT" 2>&1; rc=$?
  got=$(grep -o "^VERIFY FAIL V[0-9]*" "$OUT" | cut -d" " -f3 | sort -u | paste -sd,)
  exp="${EXP[$k]}"; ok=0
  if [[ "$exp" == *+* ]]; then ok=1; IFS=+ read -ra need <<< "$exp"; for v in "${need[@]}"; do grep -q "^VERIFY FAIL $v:" "$OUT" || ok=0; done
  else IFS="|" read -ra any <<< "$exp"; for v in "${any[@]}"; do grep -q "^VERIFY FAIL $v:" "$OUT" && ok=1; done; fi
  nm="${NAME[$k]:-}"; [ $k -eq 15 ] && nm=$(echo "$msg" | sed -n 's/.*TARGET=\([^ ]*\).*/\1/p')
  [ -n "$nm" ] && { grep -q "^VERIFY FAIL ${exp%%[+|]*}:.*$nm" "$OUT" || ok=0; }
  [ $rc -eq 1 ] || ok=0
  [ $ok -eq 1 ] && r=PASS || r=FAIL
  echo "NC-VF-$k $r $exp ${got:-none} $msg" | cut -c1-200
  grep "^VERIFY FAIL" "$OUT" | grep -E "^VERIFY FAIL (${exp//[+|]/|}):" | head -2 | cut -c1-220
  rm -rf "$W"
done
