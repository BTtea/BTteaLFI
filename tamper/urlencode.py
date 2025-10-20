# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

# page=C:/windows/win.ini  =>  page=C%3A%2Fwindows%2Fwin.ini

from urllib.parse import quote

def tamper(payload:str):
    if payload:
        payload=quote(payload, safe='', encoding='utf-8')
    return payload