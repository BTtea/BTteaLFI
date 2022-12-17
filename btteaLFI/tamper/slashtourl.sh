#!/bin/sh

# =====================
# for slash to url encode
# =====================

# /etc/passwd => %2fetc%2fpasswd

TempPayload="$1"
if [ "$TempPayload" != "" ];then
    echo "${TempPayload//\//%2f}"
fi