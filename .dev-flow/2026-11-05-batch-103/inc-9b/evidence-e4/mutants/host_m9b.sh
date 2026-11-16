#!/bin/bash
set -euo pipefail
S="$HOME/work/zq-m9b"
PY="$HOME/miniconda3/envs/s19ci/bin/python"
ACTION="${1:?usage: host_m9b.sh launch|stop|cleanup}"
PATTERN="m9b""_driver.py"

recorded_driver_matches() {
    local pid args
    test -f "$S/driver.pid" || return 1
    pid="$(cat "$S/driver.pid")"
    test -r "/proc/$pid/cmdline" || return 1
    args="$(tr '\0' ' ' < "/proc/$pid/cmdline")"
    case "$args" in
        *"$PATTERN"*) return 0 ;;
        *) return 1 ;;
    esac
}

case "$ACTION" in
    launch)
        : "${RUNNER_HOME_NAME:?isolated HOME basename required}"
        test -f "$S/source.tar"
        test -f "$S/mutation_spec.py"
        test -f "$S/m9b_driver.py"
        test ! -e "$S/driver.pid"
        export RUNNER_HOME_NAME
        umask 077
        setsid nohup "$PY" -I -B "$S/m9b_driver.py" > "$S/driver.log" 2>&1 < /dev/null &
        pid=$!
        printf '%s\n' "$pid" > "$S/driver.pid"
        printf 'DRIVER_PID=%s\n' "$pid"
        ;;
    stop)
        if ! recorded_driver_matches; then
            printf 'RECORDED_DRIVER_NOT_RUNNING\n'
            exit 0
        fi
        pid="$(cat "$S/driver.pid")"
        sid="$(ps -o sid= -p "$pid" | tr -d ' ')"
        test -n "$sid"
        if test "$sid" = "$pid"; then
            kill -TERM -- "-$sid"
            printf 'SIGTERM_SID=%s\n' "$sid"
        else
            kill -TERM "$pid"
            printf 'SIGTERM_PID=%s\n' "$pid"
        fi
        ;;
    cleanup)
        if recorded_driver_matches; then
            printf 'DRIVER_STILL_RUNNING\n' >&2
            exit 1
        fi
        rm -rf -- \
            "$S/groups" \
            "$S/pristine" \
            "$S/out" \
            "$S/home" \
            "$S/x" \
            "$S/tmp"
        rm -f -- \
            "$S/source.tar" \
            "$S/mutation_spec.py" \
            "$S/m9b_driver.py" \
            "$S/host_m9b.sh" \
            "$S/validate_and_render.py" \
            "$S/retry_m9b.py" \
            "$S/host_retry_m9b.sh" \
            "$S/sanitize_evidence.py" \
            "$S/driver.log" \
            "$S/driver.pid" \
            "$S/retry.log" \
            "$S/retry.pid" \
            "$S/current.json" \
            "$S/selftest-assertion.xml" \
            "$S/selftest-crash.xml" \
            "$S/selftest-green.xml" \
            "$S/selftest-empty.xml"
        rmdir "$S"
        printf 'SCRATCH_REMOVED=%s\n' '~/work/zq-m9b'
        ;;
    *)
        printf 'UNKNOWN_ACTION=%s\n' "$ACTION" >&2
        exit 2
        ;;
esac
