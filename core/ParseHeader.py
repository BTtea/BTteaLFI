# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

class ParseHeaders:
    def __init__(self,res):
        parse=self.parse_http_response(res)
        self.parse=parse
        self.response=self.parse['response']
        self.head=self.parse['head']
        self.http_version=self.parse['http_version']
        self.status_code=self.parse['status_code']
        self.reason_phrase=self.parse['reason']
        self.body=self.parse['body']
    
    def parse_http_response(self,raw_response:str):
        # 分隔 header 和 body
        header_part, body = raw_response.split('\r\n\r\n', 1)

        # 拆行
        header_lines = header_part.splitlines()

        # 解析狀態列（第一行）
        status_line = header_lines[0].strip()
        http_version, status_code, *reason = status_line.split()
        reason_phrase = ' '.join(reason)

        return {
            'response':raw_response,
            'head':header_part,
            'http_version': http_version,
            'status_code': int(status_code),
            'reason': reason_phrase,
            'body': body.strip()
        }
