# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

from lib.utils.my_functions import MsgEvent
class Headers:
    def __init__(self,args,content_type,debug_level):
        self.method=args.method
        self._random_agent=args.random_agent
        self.http_version='HTTP/1.1'
        self.header=self.build_headers(args,content_type)
        self.check_headers(debug_level)

    def check_headers(self,debug_level):
        if self.is_defined('User-Agent') and self._random_agent:
            self._random_agent=False
            print(MsgEvent(debug_level,'WARNING',"Using a custom User-Agent header while also specifying the '--random-agent' option."),end='')
            print(MsgEvent(debug_level,'DEBUG',"Using a custom User-Agent."),end='')
        
        if self.is_defined('Content-Length'):
            print(MsgEvent(debug_level,'WARNING',"Defining the Content-Length header manually is not allowed."),end='')
            print(MsgEvent(debug_level,'DEBUG',"'Content-Length' is set automatically based on the request body."),end='')
            del self.header["Content-Length"]

        if self.is_defined('Connection'):
            print(MsgEvent(debug_level,'WARNING',"Defining the Connection header in custom request headers is not allowed."),end='')
            print(MsgEvent(debug_level,'DEBUG',"Set Connection header to 'close'."),end='')
            del self.header["Connection"]
        

    def build_headers(self,args,content_type):
        header={
            'Cache-Control':' no-cache',
            'Accept'       : ' */*'
        }
        if content_type:
            header['Content-Type']=content_type
        if args.header:
            for i in args.header:
                key,value=i.split(':')
                key=key.strip()
                header[key]=value
        return header
    
    def header_to_string(self):
        header=[]
        for key,value in self.header.items():
            header.append(f'{key}:{value}')
        return '\r\n'.join(header)
    
    def random_agent(self):
        from random import choice
        with open("./data/txt/user-agents.txt") as f:
            user_agents_list = [line.strip() for line in f if line.strip()]
        while True:
            agent=choice(user_agents_list)
            if not agent.startswith('#'):
                break
        return agent
    
    def is_defined(self,header_name):
        return True if header_name in self.header else False
