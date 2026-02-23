# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.


# class RequestPacket:
#     def __init__(self):
#         pass

class ResponsePacket:
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



def test_connectivity(target,argv={"POST":"","GET":""}):
    from copy import deepcopy
    from lib.utils.my_functions import MsgEvent,AskQuestion

    tmp_target=deepcopy(target)

    tmp_target.parameters.url.get_query=tmp_target.parameters.url.get_query.replace('*','')
    tmp_target.parameters.post.post_query=tmp_target.parameters.post.post_query.replace('*','')

    req=build_headers(tmp_target,argv=argv)
    print(MsgEvent(tmp_target.debug_level(),'TRAFFIC OUT',f'HTTP request:\n{req}'),end='')
        
    res=''
    for retry in range(target.args.retries):
        try:
            res=SendRequest(tmp_target,req)
        except KeyboardInterrupt:
            print(MsgEvent(target.debug_level(),'WARNING',f'user aborted during detection phase'),end='')
            question = f"how do you want to proceed? [(K)eep testing/(q)uit] "
            _choices = ['K','q']
            default  = 'K'
            tmp_target.args.batch=False
            r=AskQuestion(question,_choices,default,tmp_target)
            if r=='K':
                retry-=1
                continue
            return r
        except Exception as e:
            print(MsgEvent(tmp_target.debug_level(),'CRITICAL',f'connection timed out to the target URL. sqlmap is going to retry the request(s)'),end='')
            print(MsgEvent(tmp_target.debug_level(),'DEBUG',f'connection timed out to the target URL. sqlmap is going to retry the request'),end='')
        if res:
            break
        
    if res=='':
        print(MsgEvent(tmp_target.debug_level(),'WARNING',f"if the problem persists please check that the provided target URL is reachable. In case that it is, you can try to rerun with switch '--random-agent' and/or '--tamper option (e.g. --tamper dotslashobfuscate)'",BoldFlag=True),end='')
        return res

    res_content=ResponsePacket(res)
    print(MsgEvent(tmp_target.debug_level(),'TRAFFIC IN',f'HTTP response ({res_content.status_code} {res_content.reason_phrase}):\n{res_content.response if tmp_target.debug_level()>=6 else res_content.head}'),end='')

    return res_content


def build_headers(target,argv={"POST":"","GET":""}):
    uri=target.parameters.url.uri

    if target.parameters.url.get_query:
        uri+=f"?{target.parameters.url.get_query}"
    uri+=argv["GET"]
  
    Host=target.parameters.url.netloc

    req=f"{target.method()} {uri} {target.headers.http_version}\r\n" \
        f"Host: {Host}\r\n" \
    
    # cookie
    if target.parameters.cookie.cookies:
        req+=f"Cookie: {target.parameters.cookie.cookies}\r\n"

    # header
    if not target.headers.is_defined('User-Agent'):
        if target.args.random_agent:
            req+=f"User-Agent: {target.headers.random_agent()}\r\n"
        else:
            req+=f"User-Agent: bttealfi/{target.version} ({target.github_url})\r\n"
    req+=f"{target.headers.header_to_string()}\r\n"

    # post
    if target.parameters.post.post_query:
        req+=f"Content-Length: {len(target.parameters.post.post_query)}\r\n"

    req+=f"Connection: close\r\n\r\n"

    # post body
    if target.parameters.post.post_query:
        req+=f"{target.parameters.post.post_query}{argv['POST']}\r\n"

    return req


def SendRequest(target, req: str, binary: bool = False):
    import socket
    import ssl

    request = socket.create_connection((target.parameters.url.domain, target.parameters.url.port), timeout=target.args.timeout)

    if target.parameters.url.protocol == 'https':
        request = ssl.create_default_context().wrap_socket(request, server_hostname=target.parameters.url.domain)

    request.sendall(req.encode())
    response = b""
    while True:
        data = request.recv(4096)
        if not data:
            break
        response += data

    if binary:
        # 回傳 bytes（適合下載圖片、檔案）
        return response
    else:
        # 嘗試解碼文字，錯誤時保留不合法字元
        return response.decode(errors="replace")




