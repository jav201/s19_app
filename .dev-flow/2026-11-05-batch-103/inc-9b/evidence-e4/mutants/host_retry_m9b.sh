#!/bin/bash
set -euo pipefail
S="$HOME/work/zq-m9b"
PY="$HOME/miniconda3/envs/s19ci/bin/python"
ACTION="${1:?usage: host_retry_m9b.sh launch|stop}"
PATTERN="retry""_m9b.py"

recorded_driver_matches() {
    local pid args
    test -f "$S/retry.pid" || return 1
    pid="$(cat "$S/retry.pid")"
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
        test -f "$S/out/DONE"
        test -f "$S/retry_m9b.py"
        test ! -e "$S/retry.pid"
        export RUNNER_HOME_NAME
        umask 077
        setsid nohup "$PY" -I -B "$S/retry_m9b.py" > "$S/retry.log" 2>&1 < /dev/null &
        pid=$!
        printf '%s\n' "$pid" > "$S/retry.pid"
        printf 'RETRY_PID=%s\n' "$pid"
        ;;
    stop)
        if ! recorded_driver_matches; then
            printf 'RECORDED_RETRY_NOT_RUNNING\n'
            exit 0
        fi
        pid="$(cat "$S/retry.pid")"
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
    *)
        printf 'UNKNOWN_ACTION=%s\n' "$ACTION" >&2
        exit 2
        ;;
esac
