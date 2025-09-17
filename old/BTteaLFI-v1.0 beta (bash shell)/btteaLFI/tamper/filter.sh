#!/bin/sh

# =========================
# Used when filtering "../"
# =========================

# ../../etc/passwd => ....//....//etc/passwd

TempPayload="$1"
if [ "$TempPayload" != "" ];then
    echo "${TempPayload//..\//....\/\/}"
fi
