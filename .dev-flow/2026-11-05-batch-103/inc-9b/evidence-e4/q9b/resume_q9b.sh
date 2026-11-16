#!/usr/bin/env bash
set -u -o pipefail

S="$HOME/work/zq-q9b"
OUT="$S/out/q9b"
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

test -f "$OUT/status.tsv"

has_row() {
    awk -F '\t' -v family="$1" -v side="$2" -v label="$3" -v run="$4" '
        $1 == family && $2 == side && $3 == label && $4 == run { found = 1 }
        END { exit !found }
    ' "$OUT/status.tsv"
}

for side in base tip; do
    for label in 29_1 29_2 82_1 20_1; do
        case "$label" in
            29_1) node='tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_29_1_a_cursor_key_over_a_previewed_large_edit_is_handled_within_half_a_second' ;;
            29_2) node='tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_29_2_a_cursor_key_while_the_preview_result_arrives_is_handled_within_one_second' ;;
            82_1) node='tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_82_1_a_key_is_handled_within_one_second_while_a_record_encode_runs' ;;
            20_1) node='tests/test_b103_inc9_w_jobs.py::test_r_pe_bench_20_1_a_key_is_handled_within_half_a_second_while_a_large_decode_runs' ;;
        esac
        for run in 01 02 03 04 05; do
            if has_row oe "$side" "$label" "$run"; then
                continue
            fi
            run_one oe "$side" "$label" "$run" "$node" || exit $?
        done
    done
done

for side in base tip; do
    if ! has_row fx9c "$side" parts 01; then
        run_one fx9c "$side" parts 01 tests/test_fx9c_probe.py::test_probe_parts || exit $?
    fi
done

for label in 94_1 94_2 94_3 97_1 97_3 98_1 99_1; do
    case "$label" in
        94_1) node='tests/test_b103_inc9b_at.py::test_r_pe_bench_94_1_large_selected_shows_the_busy_border_and_title_within_half_a_second' ;;
        94_2) node='tests/test_b103_inc9b_at.py::test_r_pe_bench_94_2_a_gated_preview_shows_the_busy_title_within_half_a_second_of_enter' ;;
        94_3) node='tests/test_b103_inc9b_at.py::test_r_pe_bench_94_3_a_gated_record_stage_shows_the_busy_title_within_half_a_second_of_alt_s' ;;
        97_1) node='tests/test_b103_inc9b_at.py::test_r_pe_bench_97_1_every_tick_of_larges_real_decode_paints_a_different_title' ;;
        97_3) node='tests/test_b103_inc9b_at.py::test_r_pe_bench_97_3_the_gaps_between_changed_titles_stay_within_the_bounds' ;;
        98_1) node='tests/test_b103_inc9b_at.py::test_r_pe_bench_98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record' ;;
        99_1) node='tests/test_b103_inc9b_at.py::test_r_pe_bench_99_1_a_key_pressed_when_the_write_step_ends_is_handled_within_one_second' ;;
    esac
    for run in 01 02 03 04 05; do
        if has_row timing tip "$label" "$run"; then
            continue
        fi
        run_one timing tip "$label" "$run" "$node" || exit $?
    done
done

date --iso-8601=seconds >"$OUT/DONE"
