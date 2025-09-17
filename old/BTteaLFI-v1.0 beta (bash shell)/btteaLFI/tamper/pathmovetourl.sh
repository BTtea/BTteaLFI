#!/bin/sh

# =====================
# path move to url encode
# =====================

# ../../etc/passwd => %2e%2e%2f%2e%2e%2fetc%2fpasswd

TempPayload="$1"
if [ "$TempPayload" != "" ];then
    TempPayload="${TempPayload//./%2e}"
    TempPayload="${TempPayload//\/%2f}"
    echo "$TempPayload"
fi