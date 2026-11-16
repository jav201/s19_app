#!/usr/bin/env bash
set -u -o pipefail
S="$HOME/work/zq-q9b"
TREE="$S/tip"
OUT="$S/out/q9b"
PY="$HOME/miniconda3/envs/s19ci/bin/python"
: "${RUNNER_HOME_NAME:?set the isolated HOME basename through RUNNER_HOME_NAME}"
printf 'file\trc\n' >"$OUT/law-status.tsv"
for file in \
    tests/test_no_private_tokens.py \
    tests/test_report_markup_safety.py \
    tests/test_filename_markup_safety.py \
    tests/test_suite_hygiene.py \
    tests/test_id_registry.py
do
    test -f "$TREE/$file" || exit 2
    raw="$OUT/law-$(basename "$file" .py).txt"
    (
        cd "$TREE" || exit 125
        env -i PATH=/usr/bin:/bin \
            HOME="$S/home/$RUNNER_HOME_NAME" \
            XDG_CONFIG_HOME="$S/x/config" XDG_CACHE_HOME="$S/x/cache" \
            XDG_DATA_HOME="$S/x/data" TMPDIR="$S/tmp" \
            PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 \
            PYTHONPATH=. "$PY" -c 'import s19_app; print(s19_app.__file__)'
        uptime
        env -i PATH=/usr/bin:/bin \
            HOME="$S/home/$RUNNER_HOME_NAME" \
            XDG_CONFIG_HOME="$S/x/config" XDG_CACHE_HOME="$S/x/cache" \
            XDG_DATA_HOME="$S/x/data" TMPDIR="$S/tmp" \
            PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 \
            PYTHONPATH=. timeout 300 "$PY" -m pytest -p no:cacheprovider -n 0 -vv "$file" </dev/null
    ) >"$raw" 2>&1
    rc=$?
    printf 'Q9B_LAW_RC=%s\n' "$rc" >>"$raw"
    printf '%s\t%s\n' "$file" "$rc" >>"$OUT/law-status.tsv"
done
"$PY" "$S/sanitize_q9b.py" "$OUT"
cat "$OUT/law-status.tsv"
