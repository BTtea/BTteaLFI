# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

# page=/etc/passwd  =>  page=0x2f6574632f706173737764

def tamper(payload:str):
    return "0x" + payload.encode().hex()