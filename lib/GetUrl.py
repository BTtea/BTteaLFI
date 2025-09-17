# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

class URLobj:
    def __init__(self, url:str):
        from urllib.parse import urlparse
        if not url.startswith('http'):
            url=f'http://{url}'
        parsed = urlparse(url)
        self.url = url
        self.protocol = parsed.scheme
        self.domain = parsed.netloc.split(':',1)[0]
        self.uri = parsed.path if parsed.path else '/'
        self.get_query = parsed.query
        self.get_param = {}
        self.RenewURL()

    def RenewURL(self):
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        self.protocol = parsed.scheme
        self.domain = parsed.netloc.split(':',1)[0]
        self.uri = parsed.path if parsed.path else '/'
        self.get_query=parsed.query

        if self.get_query:
            try:
                for _get_param in self.get_query.split('&'):
                    if '=' in _get_param:
                        self.get_param[_get_param.split('=')[0]]=_get_param.split('=')[1]
            except:
                self.get_param = {}
        else:
            self.get_param = {}
        
        self.port = parsed.port if parsed.port else [80,443][self.protocol=='https']

    def __str__(self):
        return self.url

    def __repr__(self):
        return self.__str__()