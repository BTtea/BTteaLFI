# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

def SendRequest(target, req: str, binary: bool = False):
    import socket
    import ssl

    request = socket.create_connection((target.url.domain, target.url.port), timeout=target.args.timeout)

    if target.url.protocol == 'https':
        request = ssl.create_default_context().wrap_socket(request, server_hostname=target.url.domain)

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