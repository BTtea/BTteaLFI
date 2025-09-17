# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

def build_headers(target,argv={"POST":"","GET":""}):
    HTTP_Version='1.1'

    uri=target.url.uri
    if target.url.get_query:

        if not bool(target.url.get_param):
            uri+=f"?{target.url.get_query}"
        else:
            uri+="?"
            uri+=('&'.join(f'{k}={v}' for k, v in target.url.get_param.items()))

    # 如果存在*則轉空，如不想被轉則應做url encode
    uri=uri.replace('*','')
    if target.body.body:
        target.body.body=target.body.body.replace('*','')
    uri+=argv["GET"]
    
    Host=target.url.domain
    if target.url.port not in [80,443]:
        Host+=f":{target.url.port}"

    req=f"{target.method()} {uri} HTTP/{HTTP_Version}\r\n" \
        f"Host: {Host}\r\n" \
        f"{target.headers(target.body.DataType)}\r\n"

    if target.args.cookie:
        req+=f"Cookie: {target.args.cookie}\r\n"

    if target.body.body:
        req+=f"Content-Length: {len(target.body.body)}\r\n"
    
    req+=f"Connection: close\r\n\r\n"
    
    if target.body.body:
        req+=f"{target.body.body}{argv['POST']}\r\n"

    return req