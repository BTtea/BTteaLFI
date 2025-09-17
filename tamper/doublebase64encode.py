# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

from base64 import b64encode

# page=/etc/passwd  =>  page=TDJWMFl5OXdZWE56ZDJRPQ==

def tamper(payload:str):
    if payload:
        payload=b64encode(b64encode(payload.encode('utf-8'))).decode('utf-8')
    return payload