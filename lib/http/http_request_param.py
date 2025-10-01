# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

class HttpRequestParam:
    def __init__(self,target,args):
        self.url=GetUrl(args.url)
        self.post=PostBody(target,args.data)
        self.cookie=Cookies(args.cookie)
        

class GetUrl:
    def __init__(self, url:str):
        from urllib.parse import urlparse
        if not url.startswith('http'):
            url=f'http://{url}'
        parsed = urlparse(url)
        self.url = url
        # xxx.com:82
        self.netloc=parsed.netloc
        self.protocol = parsed.scheme
        self.domain = parsed.netloc.split(':',1)[0]
        self.port = parsed.port if parsed.port else [80,443][self.protocol=='https']
        self.uri = parsed.path if parsed.path else '/'
        self.get_query = parsed.query
        self.get_query_params = _parse_query(self.get_query,'&','=')
    
    def RenewURL(self):
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        # xxx.com:82
        self.netloc=parsed.netloc
        self.protocol = parsed.scheme
        self.domain = parsed.netloc.split(':',1)[0]
        self.port = parsed.port if parsed.port else [80,443][self.protocol=='https']
        self.uri = parsed.path if parsed.path else '/'
        self.get_query = parsed.query
        self.get_query_params = _parse_query(self.get_query,'&','=')

    def parse_query(self):
        if self.get_query:
            self.get_query_params = _parse_query(self.get_query,'&','=')

    def combined_query(self):
        if self.get_query_params:
            self.get_query = _combined_query(self.get_query_params,'&','=')
    
    def __str__(self):
        return self.url

    def __repr__(self):
        return self.__str__()
    

class PostBody:
    def __init__(self,target,body:str):
        self.post_query = body if body else ''
        self.post_query_params = {}
        self.content_type=''
        if self.post_query:
            self.content_type = ' application/x-www-form-urlencoded; charset=utf-8'

        if self.is_json():
            from lib.utils.my_functions import AskQuestion
            question='JSON data found in POST body. Do you want to process it? [Y/n] '
            _choices = ['Y','n']
            default  = 'Y'
            res=AskQuestion(question,_choices,default,target)
            if res == 'Y':
                self.to_json()
    
    def parse_query(self):
        if self.post_query:
            self.post_query_params = _parse_query(self.post_query,'&','=')
    
    def combined_query(self):
        if self.post_query_params:
            self.post_query = _combined_query(self.post_query_params,'&','=')

    def is_json(self):
        from json import loads
        flag=False
        try:
            _json = loads(self.post_query)
            flag=isinstance(_json, (dict, list))
        except (ValueError, TypeError):
            flag=False
        return flag

    def to_json(self):
        self.content_type = ' application/json'

    def __str__(self):
        return self.post_query

    def __repr__(self):
        return self.__str__()


class Cookies:
    def __init__(self, cookies:str):
        self.cookies=cookies
        self.cookie_params = {}

    def parse_query(self):
        if self.cookies:
            self.cookie_params = _parse_query(self.cookies,';','=')
    
    def combined_query(self):
        if self.cookie_params:
            self.cookies = _combined_query(self.cookie_params,';','=')

    def __str__(self):
        return self.cookies

    def __repr__(self):
        return self.__str__()



def _parse_query(query:str,first_split:str,second_split:str) -> dict:
    query_params = {}
    if query:
        try:
            for _get_param in query.split(first_split):
                if second_split in _get_param:
                    key=_get_param.split(second_split)[0]
                    value=_get_param.split(second_split)[1]
                    query_params[key]=value
        except:
            pass
    return query_params


def _combined_query(query_params:dict,first_split:str,second_split:str) -> str:
    query=''
    parts = []
    if query_params:
        for key, value in query_params.items():
            # v = '' if value is None else str(value)
            parts.append(f"{key}{second_split}{value}")
        query=first_split.join(parts)
    return query