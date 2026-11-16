#!/usr/bin/env bash
set -euo pipefail

SHA=$1
BUNDLE=$2
PY="$HOME/miniconda3/envs/s19ci/bin/python"
ROOT="$HOME/work/zq-x9b"
RUN="$HOME/work/x9b-run.sh"
OUT="$ROOT/final-out"
FINAL="$ROOT/final-exact"
BASE="$ROOT/base-exact"
mkdir -p "$OUT"
git clone --no-hardlinks "$BUNDLE" "$FINAL"
git -C "$FINAL" checkout --detach "$SHA"
git clone --no-hardlinks "$BUNDLE" "$BASE"
git -C "$BASE" checkout --detach e4485817d7ac3706c77f14a4c2a8cf784fe35038

NEW=(tests/test_b103_inc9b_w.py tests/test_b103_inc9b_s.py tests/test_b103_inc9b_at.py)
LAWS=(
    tests/test_address_census.py tests/test_b101_doc_hygiene.py tests/test_b101_help_legend_docs.py
    tests/test_b97_key_bar.py tests/test_deps_seam_law.py tests/test_docs_canon.py
    tests/test_engine_unchanged.py tests/test_filename_markup_safety.py tests/test_id_registry.py
    tests/test_no_private_tokens.py tests/test_report_markup_safety.py tests/test_requirements_canon.py
    tests/test_suite_hygiene.py
)
for file in "${NEW[@]}"; do
    test -f "$FINAL/$file"
done
for tree in "$FINAL" "$BASE"; do
    for file in "${LAWS[@]}" tests/test_tui_patch_json.py; do
        test -f "$tree/$file"
    done
done

run_capture() {
    local name=$1
    local tree=$2
    shift 2
    set +e
    bash "$RUN" "$tree" "$ROOT/scratch-$name" "$@" > "$OUT/$name.txt" 2>&1
    local rc=$?
    set -e
    printf '%s\n' "$rc" > "$OUT/$name.rc"
}

run_capture collect-new "$FINAL" --collect-only "${NEW[@]}"
run_capture final-w "$FINAL" tests/test_b103_inc9b_w.py
run_capture final-s "$FINAL" tests/test_b103_inc9b_s.py

AT=(
    test_r_pe_bench_94_1_large_selected_shows_the_busy_border_and_title_within_half_a_second
    test_r_pe_bench_94_2_a_gated_preview_shows_the_busy_title_within_half_a_second_of_enter
    test_r_pe_bench_94_3_a_gated_record_stage_shows_the_busy_title_within_half_a_second_of_alt_s
    test_r_pe_bench_97_1_every_tick_of_larges_real_decode_paints_a_different_title
    test_r_pe_bench_97_3_the_gaps_between_changed_titles_stay_within_the_bounds
    test_r_pe_bench_98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record
    test_r_pe_bench_99_1_a_key_pressed_when_the_write_step_ends_is_handled_within_one_second
    test_r_pe_bench_100_3_a_written_record_returns_the_window_to_its_idle_look_within_0_3_s_of_the_last_step
    test_r_pe_bench_101_2_a_record_refused_by_its_encode_returns_the_window_to_its_idle_look_within_0_3_s
    test_r_pe_bench_101_5_a_record_made_stale_by_an_undo_returns_the_window_to_its_idle_look_within_0_3_s
)
for node in "${AT[@]}"; do
    quiet=0
    for attempt in $(seq 0 30); do
        if "$PY" -I -B -c 'import os,sys; sys.exit(1 if os.getloadavg()[0] >= 1.0 else 0)'; then
            quiet=1
            break
        fi
        sleep 120
    done
    if [ "$quiet" -ne 1 ]; then
        echo "AT quiet preflight expired" >&2
        exit 1
    fi
    run_capture "final-at-$node" "$FINAL" "tests/test_b103_inc9b_at.py::$node"
done

export XDIST_N=2
run_capture collect-laws "$FINAL" --collect-only "${LAWS[@]}" tests/test_tui_patch_json.py
run_capture final-laws "$FINAL" "${LAWS[@]}"
run_capture base-laws "$BASE" "${LAWS[@]}"
run_capture final-patch-json "$FINAL" tests/test_tui_patch_json.py

printf 'FINAL_HEAD %s\n' "$(git -C "$FINAL" rev-parse HEAD)"
printf 'BASE_HEAD %s\n' "$(git -C "$BASE" rev-parse HEAD)"
printf 'FINAL_STATUS_BEGIN\n'
git -C "$FINAL" status --porcelain
printf 'FINAL_STATUS_END\nBASE_STATUS_BEGIN\n'
git -C "$BASE" status --porcelain
printf 'BASE_STATUS_END\n'
