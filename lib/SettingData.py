# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

import json
from lib.InitializationArgv import ANSIcolors,MsgEvent,AskQuestion

class ExploitDataSetting:
    def __init__(self,args,version):
        import lib.GetUrl
        import lib.PostBody
        import lib.BackendSystem
        self.args=args
        self.url=lib.GetUrl.URLobj(self.args.url)
        self.body=lib.PostBody.BodyData(self.args.data)
        self.SettingPostData()
        self.test_skip=self.TestSkip(self.args.test_skip)
        self.technique=self.Technique(self.args.technique)
        self.backend_system=lib.BackendSystem.WebTechnique()


    def answer(self):
        return self.args.answer.split(',') if self.args.answer else []

    def method(self):
        if self.args.method=='GET' and self.args.data:
            return 'POST'
        else:
            return self.args.method

    def headers(self,body_DataType=''):
        import lib.ExploitHeader
        obj=lib.ExploitHeader.header(self.args,body_DataType)
        return obj

    def SkipParam(self):
        return self.args.skip.split(',') if self.args.skip else []

    def SpecifyParam(self):
        return self.args.p.split(',') if self.args.p else []

    def Technique(self,technique):
        if technique=='':
            return ['AP','RP','PHP_F']
        technique=technique.split(',')
        for i in technique:
            if i not in ['AP','RP','PHP_F']:
                print(MsgEvent(self.DebugLevel(),'ERROR','Invalid technique specified; only AP and RP are supported.'),end='')
                exit(0)
        return technique

    def DebugLevel(self):
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

    def TestSkip(self,test_skip):
        test_skip=test_skip.split(',')
        test_skip=list(filter(None, test_skip))
        return test_skip

    def SettingPostData(self):
        if self.body:
            json_flag=self._is_json(self.body.body)
            if not json_flag and self.body.DataType=='json':
                print(MsgEvent(self.DebugLevel(),'ERROR','Detected that the header specifies the POST data type as JSON, but the POST data is not in valid JSON format.'),end='')
                exit(0)
            if json_flag:
                question='JSON data found in POST body. Do you want to process it? [Y/n] '
                _choices = ['Y','n']
                default  = 'Y'
                res=AskQuestion(question,_choices,default,self)
                
                if res == 'Y':
                    self.body.DataType='json'
                    # self.body.post_param=json.loads(self.body.body)

            # 如果是query且post_param沒設定，就初始化post data
            if bool(self.body.post_param)==False and self.body.DataType=='query':
                self.body.post_param = {
                    i.split('=')[0]: i.split('=')[1]
                    for i in self.body.body.split('&') if '=' in i
                }


    def _is_json(self,post_data):
        flag=False
        try:
            obj = json.loads(post_data)
            flag=isinstance(obj, (dict, list))
        except (ValueError, TypeError):
            flag=False
        return flag