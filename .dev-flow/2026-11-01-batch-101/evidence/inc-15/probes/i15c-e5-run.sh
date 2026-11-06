#!/usr/bin/env bash
# usage: i15c-e5-run.sh <tree-dir> <run-name> <label> <pytest args...>  (LAN Linux host)
set -u
tree="$1"; name="$2"; label="$3"; shift 3
log=/tmp/i15c/runs/$name.log
mkdir -p /tmp/i15c/runs/$name
cd "$tree" || exit 2
{
  echo "# $name: $label"
  echo "# tree: $(basename "$tree"); env: I15_HOLD=${I15_HOLD:-} I15_HOLD_ACTION=${I15_HOLD_ACTION:-} I15_NEVER=${I15_NEVER:-}"
  echo "# cmd: python -m pytest -p i15c_e5_guard -p no:cacheprovider $*"
  env -u NO_COLOR PYTHONPATH=/tmp/i15c/scripts I15C_TREE="$(basename "$tree")" \
    /data/miniconda3/envs/s19ci/bin/python -m pytest -p i15c_e5_guard -p no:cacheprovider \
    --basetemp=/tmp/i15c/runs/$name/bt "$@" 2>&1
  echo "# rc=$?"
} > "$log"
rc=$(tail -1 "$log" | sed 's/# rc=//')
echo "$name rc=$rc [$label] $(grep -E 'did not settle|^E +(assert|AssertionError|AttributeError|KeyError|textual)' "$log" | head -2 | cut -c1-150 | tr '\n' ' ')| $(grep -E '^=+ .*(passed|failed|error|no tests ran)' "$log" | tail -1)"
