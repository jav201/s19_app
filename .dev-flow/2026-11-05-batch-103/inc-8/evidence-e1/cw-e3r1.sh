#!/bin/bash
# Inc 8 E3R1 caller census (Code-Wire core: real callers via codewire_extract.py) for the existing
# functions the E3R1 rulings change or newly call. Throwaway copy of s19_app at 91d5ae56 outside
# every work tree; marks only in that copy. Args: <repo> <code-wire> <scratch> <graph>.
set -e
REPO=$1; CW=$2; SCR=$3; G=$4
rm -rf "$SCR/cwclone"; mkdir -p "$SCR/cwclone"
git -C "$REPO" archive 91d5ae56 s19_app | tar -x -C "$SCR/cwclone"
git -C "$SCR/cwclone" init -q && git -C "$SCR/cwclone" add -A && git -C "$SCR/cwclone" -c user.name=census -c user.email=census@invalid commit -q -m base
echo "code-wire: $(git -C "$CW" describe --tags)"
python -B "$CW/tools/codewire_marks.py" --repo "$SCR/cwclone" --graph "$G"
python -B "$CW/tools/codewire_extract.py" --repo "$SCR/cwclone" --graph "$G" --out "$SCR/cwout" || echo "extract exit=$?"
