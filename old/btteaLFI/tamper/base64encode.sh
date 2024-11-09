#!/bin/sh

# ===================
# for base64 encoding
# ===================

# /etc/passwd => L2V0Yy9wYXNzd2QK

TempPayload="$1"
if [ "$TempPayload" != "" ];then
    echo "$TempPayload"|base64
fi
