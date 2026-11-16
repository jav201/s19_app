#!/usr/bin/env bash
set -uo pipefail

expected="$1"
root="$HOME/work/b103-close"
repo="$root/repo"
run="$root/run-$expected"
python="$HOME/miniconda3/envs/s19ci/bin/python"
runner="$repo/.dev-flow/2026-11-05-batch-103/evidence/full-suite/run_sequential.py"
isolation="$root/ht02-$expected"

if [[ "$(git -C "$repo" rev-parse HEAD)" != "$expected" ]]; then
    printf 'HEAD mismatch\n' >&2
    exit 64
fi
if [[ -n "$(git -C "$repo" status --porcelain=v1)" ]]; then
    printf 'clone is not clean\n' >&2
    exit 65
fi
if [[ -e "$run" || -e "$isolation" ]]; then
    printf 'run or isolation path already exists\n' >&2
    exit 66
fi

umask 077
mkdir -p "$run/tmp" "$isolation/zq_b103_close/config" "$isolation/zq_b103_close/data" "$isolation/zq_b103_close/cache" "$isolation/zq_b103_close/local"
{
    printf 'date='
    date --iso-8601=seconds
    printf 'HEAD='
    git -C "$repo" rev-parse HEAD
    printf 'tree='
    git -C "$repo" rev-parse 'HEAD^{tree}'
    printf 'status='
    if [[ -z "$(git -C "$repo" status --porcelain=v1)" ]]; then
        printf 'clean\n'
    else
        printf 'dirty\n'
    fi
    printf 'loadavg='
    cat /proc/loadavg
    uptime
    printf 'python='
    "$python" --version
    printf 's19_app.__file__='
    (cd "$repo" && "$python" -I -B -c "import sys; sys.path.insert(0, '.'); import s19_app; print(s19_app.__file__)")
    printf 'runner=run_sequential.py chunks=8 sequential=yes stdin=DEVNULL bytecode=disabled pytest_cache=disabled whole_suite_timeout=none\n'
    printf 'isolation=HOME,XDG_CONFIG_HOME,XDG_DATA_HOME,XDG_CACHE_HOME,LOCALAPPDATA,TMPDIR under %s; DISPLAY unset\n' "$root"
} > "$run/environment.txt" 2>&1

export B103_FULL_SUITE_OUT="$run/out"
env -i \
    PATH="$PATH" \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    HOME="$isolation/zq_b103_close" \
    XDG_CONFIG_HOME="$isolation/zq_b103_close/config" \
    XDG_DATA_HOME="$isolation/zq_b103_close/data" \
    XDG_CACHE_HOME="$isolation/zq_b103_close/cache" \
    LOCALAPPDATA="$isolation/zq_b103_close/local" \
    TMPDIR="$run/tmp" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONIOENCODING=utf-8 \
    PYTHONUTF8=1 \
    B103_FULL_SUITE_OUT="$run/out" \
    "$python" -I -B "$runner" > "$run/launcher.txt" 2>&1 < /dev/null
rc=$?
printf '%s\n' "$rc" > "$run/full_suite_exit.txt"
{
    printf 'date='
    date --iso-8601=seconds
    printf 'HEAD='
    git -C "$repo" rev-parse HEAD
    printf 'loadavg='
    cat /proc/loadavg
    uptime
    printf 'full_suite_exit=%s\n' "$rc"
} > "$run/completion.txt" 2>&1
exit "$rc"
