#!/usr/bin/env bash
set -uo pipefail

if [ "$#" -lt 3 ]; then
    echo "usage: x9b-run.sh TREE OUTER_SCRATCH TEST [TEST ...]" >&2
    exit 2
fi
TREE=$1
SCRATCH=$2
shift 2
PY="$HOME/miniconda3/envs/s19ci/bin/python"
# HT-11: the isolated HOME basename arrives out of band, never in evidence.
: "${RUNNER_HOME_NAME:?set RUNNER_HOME_NAME to the HT-02 HOME basename}"
ISO_HOME="$SCRATCH/home/$RUNNER_HOME_NAME"
mkdir -p "$ISO_HOME" "$SCRATCH/x/config" "$SCRATCH/x/cache" "$SCRATCH/x/data" "$SCRATCH/x/state" "$SCRATCH/tmp"

printf 'DATE %s\n' "$(date -Is)"
printf 'HEAD %s\n' "$(git -C "$TREE" rev-parse HEAD)"
printf 'TREE %s\n' "$TREE"
printf 'DIRTY_BEGIN\n'
git -C "$TREE" status --porcelain
printf 'DIRTY_END\n'
uptime
cd "$TREE" || exit 2
export PYTHONIOENCODING=utf-8
set +e
env -i PATH=/usr/bin:/bin HOME="$ISO_HOME" \
    XDG_CONFIG_HOME="$SCRATCH/x/config" XDG_CACHE_HOME="$SCRATCH/x/cache" \
    XDG_DATA_HOME="$SCRATCH/x/data" XDG_STATE_HOME="$SCRATCH/x/state" \
    TMPDIR="$SCRATCH/tmp" PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 \
    LANG=C.UTF-8 "$PY" -I -B -c \
    'import os,sys; sys.path.insert(0,"."); import s19_app; print("PYTHON "+sys.version.replace("\n"," ")); print("S19_APP_FILE "+s19_app.__file__); print("UTF8 "+os.environ["PYTHONIOENCODING"])'
IMPORT_RC=$?
if [ "$IMPORT_RC" -ne 0 ]; then
    printf 'IMPORT_EXIT_CODE %s\n' "$IMPORT_RC"
    exit "$IMPORT_RC"
fi
printf 'TESTS_BEGIN'
printf ' %s' "$@"
printf '\nXDIST_N %s\n' "${XDIST_N:-0}"
timeout 300 env -i PATH=/usr/bin:/bin HOME="$ISO_HOME" \
    XDG_CONFIG_HOME="$SCRATCH/x/config" XDG_CACHE_HOME="$SCRATCH/x/cache" \
    XDG_DATA_HOME="$SCRATCH/x/data" XDG_STATE_HOME="$SCRATCH/x/state" \
    TMPDIR="$SCRATCH/tmp" PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 \
    LANG=C.UTF-8 "$PY" -I -B -m pytest -p no:cacheprovider \
    -n "${XDIST_N:-0}" -q -rf -v "$@" < /dev/null
RC=$?
printf 'EXIT_CODE %s\n' "$RC"
exit "$RC"
