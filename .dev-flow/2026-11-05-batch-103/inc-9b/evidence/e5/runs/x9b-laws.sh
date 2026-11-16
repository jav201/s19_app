#!/usr/bin/env bash
set -euo pipefail

ROOT="$HOME/work/zq-x9b"
RUN="$HOME/work/x9b-run.sh"
OUT="$ROOT/law-out"
mkdir -p "$OUT"
LAWS=(
    test_address_census.py test_b101_doc_hygiene.py test_b101_help_legend_docs.py
    test_b97_key_bar.py test_deps_seam_law.py test_docs_canon.py test_engine_unchanged.py
    test_filename_markup_safety.py test_id_registry.py test_no_private_tokens.py
    test_report_markup_safety.py test_requirements_canon.py test_suite_hygiene.py
)
export XDIST_N=2
for side in final base; do
    if [ "$side" = final ]; then TREE="$ROOT/final-exact"; else TREE="$ROOT/base-exact"; fi
    for law in "${LAWS[@]}"; do
        name="${side}-${law%.py}"
        set +e
        bash "$RUN" "$TREE" "$ROOT/scratch-$name" "tests/$law" > "$OUT/$name.txt" 2>&1
        rc=$?
        set -e
        printf '%s\n' "$rc" > "$OUT/$name.rc"
    done
done
