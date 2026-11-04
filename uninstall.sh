#!/system/bin/sh

PIDFILE="/dev/svc_8667d2.pid"

if [ -f "$PIDFILE" ]; then
    PID="$(cat "$PIDFILE" 2>/dev/null)"
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null
    fi
    rm -f "$PIDFILE"
fi

rm -rf /dev/svc_8667d2.lock
