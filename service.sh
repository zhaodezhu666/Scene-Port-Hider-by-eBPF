#!/system/bin/sh
MODDIR=${0%/*}

sh "$MODDIR/run.sh" service >/dev/null 2>&1 &
