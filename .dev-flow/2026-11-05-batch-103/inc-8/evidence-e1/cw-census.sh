#!/bin/bash
# Inc 8 E1 caller census (Code-Wire core: real callers via codewire_extract.py).
# Throwaway copy of s19_app at 91d5ae56 outside every work tree; marks only in that copy.
set -e
REPO=$1; CW=$2; SCR=$3; G=$4
rm -rf "$SCR/clone"; mkdir -p "$SCR/clone"
git -C "$REPO" archive 91d5ae56 s19_app | tar -x -C "$SCR/clone"
# codewire_marks.py needs a git work tree: a throwaway one-commit repo.
git -C "$SCR/clone" init -q && git -C "$SCR/clone" add -A && git -C "$SCR/clone" -c user.name=census -c user.email=census@invalid commit -q -m base
echo "code-wire: $(git -C "$CW" describe --tags)"
python -B "$CW/tools/codewire_marks.py" --repo "$SCR/clone" --graph "$G"
python -B "$CW/tools/codewire_extract.py" --repo "$SCR/clone" --graph "$G" --out "$SCR/out" || echo "extract exit=$?"
