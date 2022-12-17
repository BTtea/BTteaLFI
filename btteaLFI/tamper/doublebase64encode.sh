#!/bin/sh

# ==========================
# for base64 double encoding
# ==========================

# /etc/passwd => TDJWMFl5OXdZWE56ZDJRSwo=

TempPayload="$1"
if [ "$TempPayload" != "" ];then
    echo "$TempPayload"|base64|base64
fi