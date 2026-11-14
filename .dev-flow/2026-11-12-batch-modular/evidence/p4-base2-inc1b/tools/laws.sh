#!/usr/bin/env bash
# Check (b): the brief's laws plus those named in CLAUDE.md, on merged and on base a95d0ea9.
set -u
S=$HOME/work/zq-base2
L="tests/test_no_private_tokens.py tests/test_package_source_helper.py tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_import_census.py tests/test_deps_seam_law.py tests/test_engine_unchanged.py tests/test_id_registry.py"
for t in merged base; do
  for f in $L tests/test_tui_directionb.py; do test -f "$S/$t/$f" || echo "MISSING $t/$f"; done
  bash "$S/run_t.sh" "$S/$t" "$S/out-b-$t" 4 1800 $L
  bash "$S/run_t.sh" "$S/$t" "$S/out-b31-$t" 0 900 tests/test_tui_directionb.py -k tc031
done
for o in out-b-merged out-b31-merged out-b-base out-b31-base; do echo "$o rc=$(cat $S/$o/rc)"; grep -E '^(FAILED|ERROR)|passed|failed' "$S/$o/run.txt" | tail -8; done
echo LAWS_DONE
