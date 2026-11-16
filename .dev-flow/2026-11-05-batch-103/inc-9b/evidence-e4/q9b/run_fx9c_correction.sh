#!/usr/bin/env bash
set -u -o pipefail

S="$HOME/work/zq-q9b"
OUT="$S/out/fx9c-correction"
PY="$HOME/miniconda3/envs/s19ci/bin/python"
REAL_HOME="$HOME"
: "${RUNNER_HOME_NAME:?set the isolated HOME basename through RUNNER_HOME_NAME}"
mkdir -p "$OUT" "$S/home/$RUNNER_HOME_NAME" "$S/x/config" "$S/x/cache" "$S/x/data" "$S/tmp"

sanitize() {
    "$PY" - "$1" "$REAL_HOME" "$S/home/$RUNNER_HOME_NAME" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = path.read_bytes()
for old, new in (
    (sys.argv[3].encode(), b"<runner-home>"),
    (sys.argv[2].encode(), b"~"),
):
    data = data.replace(old, new)
path.write_bytes(data)
PY
}

wait_quiet() {
    local attempt=0 line load
    while true; do
        line=$(uptime)
        printf '%s\n' "$line"
        load=$(printf '%s\n' "$line" | awk '{gsub(/,/, "", $(NF-2)); print $(NF-2)}')
        if awk -v value="$load" 'BEGIN { exit !(value < 1.0) }'; then
            QUIET_LOAD="$load"
            printf 'Q9B_LOAD1=%s\n' "$QUIET_LOAD"
            return 0
        fi
        if [ "$attempt" -eq 30 ]; then
            printf 'Q9B_NOT_MEASURED_LOAD=%s\n' "$load"
            return 1
        fi
        attempt=$((attempt + 1))
        sleep 120
    done
}

run_one() {
    local family="$1" side="$2" label="$3" run="$4" node="$5"
    local tree="$S/$side" raw="$OUT/${family}-${side}-${label}-${run}.txt"
    local test_rc valid_rc
    local -a extra=()
    if [ "$family" = gap ]; then
        extra=("Q9B_SCENARIO=$label" "Q9B_RUN=$run")
    fi

    (
        cd "$tree" || exit 125
        env -i PATH=/usr/bin:/bin \
            HOME="$S/home/$RUNNER_HOME_NAME" \
            XDG_CONFIG_HOME="$S/x/config" XDG_CACHE_HOME="$S/x/cache" \
            XDG_DATA_HOME="$S/x/data" TMPDIR="$S/tmp" \
            PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 \
            PYTHONPATH=. "$PY" -c \
            'import s19_app; print(s19_app.__file__)'
    ) >"$raw" 2>&1
    printf 'Q9B_FAMILY=%s Q9B_SIDE=%s Q9B_LABEL=%s Q9B_RUN=%s\n' \
        "$family" "$side" "$label" "$run" >>"$raw"
    printf 'Q9B_HEAD=%s\n' "$(git -C "$tree" rev-parse HEAD)" >>"$raw"

    if ! wait_quiet >>"$raw" 2>&1; then
        sanitize "$raw"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$family" "$side" "$label" "$run" "not-measured-load" "FAIL" "$raw" >>"$OUT/status.tsv"
        return 2
    fi

    printf 'Q9B_NODE=%s\n' "$node" >>"$raw"
    (
        cd "$tree" || exit 125
        env -i PATH=/usr/bin:/bin \
            HOME="$S/home/$RUNNER_HOME_NAME" \
            XDG_CONFIG_HOME="$S/x/config" XDG_CACHE_HOME="$S/x/cache" \
            XDG_DATA_HOME="$S/x/data" TMPDIR="$S/tmp" \
            PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 \
            PYTHONPATH=. "${extra[@]}" \
            timeout 300 "$PY" -m pytest -p no:cacheprovider -n 0 -vv -s "$node" \
            </dev/null
    ) >>"$raw" 2>&1
    test_rc=$?
    printf 'Q9B_RC=%s\n' "$test_rc" >>"$raw"
    sanitize "$raw"
    "$PY" "$S/validate_q9b.py" "$raw" "$family" "$label" "$run" >>"$raw" 2>&1
    valid_rc=$?
    sanitize "$raw"
    if [ "$valid_rc" -eq 0 ]; then
        valid=PASS
    else
        valid=FAIL
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$family" "$side" "$label" "$run" "$test_rc" "$valid" "$QUIET_LOAD" "${raw#$S/}" \
        >>"$OUT/status.tsv"
    return 0
}

printf 'family\tside\tlabel\trun\ttest_rc\tvalidation\tload1\ttranscript\n' >"$OUT/status.tsv"

for side in base tip; do
    run_one fx9c "$side" parts 02 tests/test_fx9c_q9b_probe.py::test_probe_parts || exit $?
done

date --iso-8601=seconds >"$OUT/DONE"
