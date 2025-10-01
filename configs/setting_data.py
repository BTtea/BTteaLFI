# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

from lib.utils.my_functions import MsgEvent

class ExploitDataSetting:
    def __init__(self,args,version,github_url):
        from lib.http.http_request_param import HttpRequestParam
        from lib.http.headers import Headers
        from lib.detect.backend_technique import WebTechnique
        self.version=version
        self.github_url=github_url
        self.args=args
        self.args.method=self.method()
        self.parameters=HttpRequestParam(self,args)
        self.headers=Headers(args,self.parameters.post.content_type,self.debug_level())
        if self.headers.is_defined('User-Agent') and self.args.random_agent:
            self.args.random_agent=False
        self.test_skip=self.test_skip(self.args.test_skip)
        self.technique=self.check_technique(self.args.technique)
        self.web_backend_technique=WebTechnique(args)


    def answer(self):
        return self.args.answer.split(',') if self.args.answer else []

    def method(self):
        if self.args.method=='GET' and self.args.data:
            return 'POST'
        else:
            return self.args.method

    def SkipParam(self):
        return self.args.skip.split(',') if self.args.skip else []

    def SpecifyParam(self):
        return self.args.p.split(',') if self.args.p else []

    def check_technique(self,technique):
        if technique==[]:
            return ['AP','RP','PHP_F']
        technique=technique.split(',')
        for i in technique:
            if i not in ['AP','RP','PHP_F']:
                print(MsgEvent(self.debug_level(),'ERROR','Invalid technique specified; only AP and RP are supported.'),end='')
                exit(0)
        return technique

    def debug_level(self):
        return self.args.v

    def tampers(self):
        from pathlib import Path
        if self.args.tamper:
            tamper_files = [f.name for f in Path("./tamper").iterdir() if f.is_file() and f.suffix == ".py"]
            for scan in self.args.tamper.split(','):
                if f'{scan}.py' not in tamper_files:
                    print(MsgEvent(self.DebugLevel(),'CRITICAL',f"tamper script '{scan}' does not exist"),end='')
                    exit(0)

        return self.args.tamper.split(',') if self.args.tamper else []

    def test_skip(self,test_skip):
        test_skip=test_skip.split(',')
        test_skip=list(filter(None, test_skip))
        return test_skip