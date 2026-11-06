#!/usr/bin/env bash
# usage: i15-run.sh <run-name> <pytest args...>   (cwd must be the worktree)
set -u
name="$1"; shift
root=<HOME>/.claude/jobs/3f13b036/tmp/i15win/$name
mkdir -p "$root/Local" "$root/Roaming" "$root/Temp" "$root/Home" "$root/bt"
w() { cygpath -w "$1"; }
cd <HOME>/Github/s19_app-b101-inc15 || exit 2
env -u NO_COLOR \
  LOCALAPPDATA="$(w "$root/Local")" APPDATA="$(w "$root/Roaming")" \
  TEMP="$(w "$root/Temp")" TMP="$(w "$root/Temp")" \
  USERPROFILE="$(w "$root/Home")" HOME="$(w "$root/Home")" \
  PYTHONPATH="$(w <HOME>/.claude/jobs/3f13b036/tmp/i15win/scripts)" \
  <HOME>/anaconda3/envs/s19env/python.exe -m pytest -p i15_guard -p no:cacheprovider \
  --basetemp="$(w "$root/bt")" "$@"
