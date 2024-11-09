#!/bin/sh

# =====================
# for slash url double encode
# =====================

# /etc/apsswd => %252fetc%252fpasswd

TempPayload="$1"
if [ "$TempPayload" != "" ];then
    echo "${TempPayload//\//%252f}"
fi