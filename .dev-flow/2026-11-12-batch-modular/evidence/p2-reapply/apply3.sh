#!/usr/bin/env bash
# re-apply 2 (P2 RC-A/B): from base with the T6 census/retargeter (b5f5e962). Product+tests reset to pre-apply 62b6e712,
# then the post-apply test commits that are not retargeter output are restored from HEAD (P1c helper c934401d, id_registry a248edb8).
set -u
A=~/work/zq-mod/apply3; rm -rf $A; mkdir -p $A/state/zq_iso_user $A/state/x $A/state/tmp
git clone -q /tmp/zq-fix3.bundle $A/tree 2>/dev/null; cd $A/tree && git checkout -q -b batch-modular-apply origin/batch-modular-apply
HEAD0=$(git rev-parse HEAD)
git rm -r -q s19_app/tui/app s19_app/tui/screens_directionb && git checkout 62b6e712 -- s19_app tests && echo "reset_rc=$?"
git checkout $HEAD0 -- tests/support/package_source.py tests/test_package_source_helper.py tests/test_id_registry.py && echo "restore_rc=$?"
M=.dev-flow/2026-11-12-batch-modular/design/module-map.json; R=.dev-flow/2026-11-12-batch-modular/design/retarget-accepted-refusals.txt
PY=/data/miniconda3/envs/s19ci/bin/python
E="env -i PATH=/usr/bin:/bin HOME=$A/state/zq_iso_user TMPDIR=$A/state/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8"
echo "== MOVE"; $E /usr/bin/python3 -I -B tools/modularize/move.py --repo . --rev 4f721985 --map $M --py $PY < /dev/null; echo "move_rc=$?"
echo "== VERIFY"; $E /usr/bin/python3 -I -B tools/modularize/verify.py --repo . --base-rev 4f721985 --map $M --py $PY --state $A/state --json $A/verify.json < /dev/null | tail -25; echo "verify_rc=${PIPESTATUS[0]}"
echo "== RETARGET"; $E /usr/bin/python3 -I -B tools/modularize/retarget_tests.py --repo . --map $M --accept-refusal $R < /dev/null | tail -5; echo "rt_rc=${PIPESTATUS[0]}"
$E /usr/bin/python3 -I -B tools/modularize/retarget_tests.py --repo . --map $M --check --accept-refusal $R < /dev/null | tail -2; echo "rtc_rc=${PIPESTATUS[0]}"
git add -A s19_app tests
echo "== DIFF vs $HEAD0 (expect deps.py + the 4 D1 call-site modules + tests/test_b100_workers.py)"; git diff --cached --stat $HEAD0 -- s19_app tests
find . -name __pycache__ -newer /tmp/zq-fix3.bundle -not -path ./.git | head -3
echo APPLY_DONE
