#!/usr/bin/env bash
set -euo pipefail

SHA=$1
BUNDLE=$2
PY="$HOME/miniconda3/envs/s19ci/bin/python"
ROOT="$HOME/work/zq-x9b"
RUN="$HOME/work/x9b-run.sh"
CONTROL="$HOME/work/x9b_control.py"
for name in residual-base residual-sync residual-later residual-stall residual-chain; do
    git clone --no-hardlinks "$BUNDLE" "$ROOT/$name"
    git -C "$ROOT/$name" checkout --detach "$SHA"
done
"$PY" -I -B "$CONTROL" "$ROOT/residual-sync" sync-worker-valid
"$PY" -I -B "$CONTROL" "$ROOT/residual-later" later-raise-valid
"$PY" -I -B "$CONTROL" "$ROOT/residual-stall" stall-sheet
"$PY" -I -B "$CONTROL" "$ROOT/residual-chain" chain

run_node() {
    local label=$1
    local tree=$2
    local node=$3
    printf '\nCONTROL_PHASE %s\n' "$label"
    bash "$RUN" "$tree" "$ROOT/scratch-$label" "$node"
    printf 'CONTROL_RC %s %s\n' "$label" "$?"
}

set +e
N98=tests/test_b103_inc9b_at.py::test_r_pe_bench_98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record
N99=tests/test_b103_inc9b_at.py::test_r_pe_bench_99_1_a_key_pressed_when_the_write_step_ends_is_handled_within_one_second
N97=tests/test_b103_inc9b_at.py::test_r_pe_bench_97_3_the_gaps_between_changed_titles_stay_within_the_bounds
LATER=tests/test_b103_inc9b_s.py::test_r_pe_bench_98_2_a_later_step_raise_releases_record_done_exactly_once
run_node baseline-98 "$ROOT/residual-base" "$N98"
run_node baseline-99 "$ROOT/residual-base" "$N99"
run_node stall-98 "$ROOT/residual-stall" "$N98"
run_node stall-99 "$ROOT/residual-stall" "$N99"
run_node chain-98 "$ROOT/residual-chain" "$N98"
run_node chain-99 "$ROOT/residual-chain" "$N99"
run_node sync-97 "$ROOT/residual-sync" "$N97"
run_node later-raise "$ROOT/residual-later" "$LATER"
