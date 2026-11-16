#!/usr/bin/env bash
# re-apply from base with fixed tools (review F1/F2). Product+tests reset to pre-apply 62b6e712, tools/records from HEAD.
set -u
A=~/work/zq-mod/apply2; rm -rf $A; mkdir -p $A/state/zq_iso_user $A/state/x $A/state/tmp
git clone -q /tmp/zq-fix2.bundle $A/tree 2>/dev/null; cd $A/tree && git checkout -q -b batch-modular-apply origin/batch-modular-apply
HEAD0=$(git rev-parse HEAD)
git rm -r -q s19_app/tui/app s19_app/tui/screens_directionb && git checkout 62b6e712 -- s19_app tests && echo "reset_rc=$?"
M=.dev-flow/2026-11-12-batch-modular/design/module-map.json; PY=/data/miniconda3/envs/s19ci/bin/python
E="env -i PATH=/usr/bin:/bin HOME=$A/state/zq_iso_user TMPDIR=$A/state/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8"
echo "== MOVE"; $E /usr/bin/python3 -I -B tools/modularize/move.py --repo . --rev 4f721985 --map $M --py $PY < /dev/null; echo "move_rc=$?"
echo "== VERIFY"; $E /usr/bin/python3 -I -B tools/modularize/verify.py --repo . --base-rev 4f721985 --map $M --py $PY --state $A/state --json $A/verify.json < /dev/null | tail -25; echo "verify_rc=${PIPESTATUS[0]}"
echo "== RETARGET"; $E /usr/bin/python3 -I -B tools/modularize/retarget_tests.py --repo . --map $M < /dev/null | tail -5; echo "rt_rc=${PIPESTATUS[0]}"
$E /usr/bin/python3 -I -B tools/modularize/retarget_tests.py --repo . --map $M --check < /dev/null | tail -2
git add -A s19_app tests
echo "== DIFF vs $HEAD0 (expect only deps.py + loaded_artifacts.py)"; git diff --cached --stat $HEAD0 -- s19_app tests
find . -name __pycache__ -newer /tmp/zq-fix2.bundle -not -path ./.git | head -3
echo APPLY_DONE
