# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

import re

def CheckBackendApp(target,head:str):
    from lib.utils.my_functions import MsgEvent,AskQuestion
    from lib.detect.backend_technique import WebTechnique

    obj=WebTechnique(target.args)
    
    backend_apps=['php','asp','aspx','jsp','nodejs']
    head_tmp=head.lower()
    for i in backend_apps:
        backend_flag=False
        if i in head_tmp:
            backend_flag=True
            print(MsgEvent(target.debug_level(),'INFO',f"Detected that the HTTP response headers disclose the backend technology as '{i.upper()}'.",BoldFlag=True),end='')

        if target.parameters.url.uri.endswith(f".{i}"):
            backend_flag=True
            print(MsgEvent(target.debug_level(),'INFO',f"Detected URI suffix is '.{i}'.",BoldFlag=True),end='')

        if backend_flag:
            question=f"The detected backend technology appears to be '{i.upper()}'. Would you like to skip payload tests targeting other backend technologies? [Y/n] "
            _choices=['Y','n']
            default='Y'
            res=AskQuestion(question,_choices,default,target)

            if res=='Y':
                obj.app_type=i.upper()
                target.args.backend_app=i.upper()
                target.web_backend_technique.app_user_choose=res
                break
            
            if obj.app_type=='' and target.args.backend_app != 'all':
                obj.app_type=target.args.backend_app.upper()

    if obj.app_type=='' and target.args.backend_app != 'all':
        obj.app_type=target.args.backend_app.upper()

    all_os={
        'CentOS'  : 'linux',
        'Unix'    : 'linux',
        'Ubuntu'  : 'linux',
        'Debian'  : 'linux',
        'Win32'   : 'windows',
        'Win64'   : 'windows'
    }

    for k,v in all_os.items():
        if k.lower() in head.lower():
            obj.os_type=v
            obj.os_version=k
            print(MsgEvent(target.debug_level(),'INFO',f"Detected that the HTTP response header discloses the operating system type as '{k}'",BoldFlag=True),end='')

            question=f"The detected operating system appears to be '{v}'. Do you want to skip payload tests intended for other operating systems? [Y/n] "
            _choices=['Y','n']
            default='Y'
            res=AskQuestion(question,_choices,default,target)

            if res=='Y':
                target.args.os=all_os[k]
                obj.os_type=all_os[k]
                target.web_backend_technique.app_user_choose=res
                break
            
            if obj.os_type=='' and target.args.os != 'all':
                obj.os_type=target.args.os.capitalize()
    
    if obj.os_type=='' and target.args.os != 'all':
        obj.os_type=target.args.os.capitalize()

    X_Powered_By=_GetBanner(head,'X-Powered-By')
    obj.app_banner=_GetBanner(head,'Server').replace(X_Powered_By,'')

    if X_Powered_By:
        obj.app_banner+=f", {X_Powered_By}" if obj.app_banner else X_Powered_By
    elif obj.app_type:
        obj.app_banner+=f", {obj.app_type}" if obj.app_banner else obj.app_type
    if obj.app_banner=='':
        obj.app_banner='Unknown'
    if obj.os_version != '':
        obj.os_banner=f'{obj.os_version} {obj.os_type}'
    else:
        obj.os_banner='Unknown'
    
    target.web_backend_technique=obj

    # reset app
    if target.web_backend_technique.app_type and target.web_backend_technique.app_user_choose== 'Y':
        target.args.backend_app=target.web_backend_technique.app_type.lower()
    # reset os
    if target.web_backend_technique.os_type and target.web_backend_technique.os_user_choose == 'Y':
        target.args.os=target.web_backend_technique.os_type.lower()

    return target



def _GetBanner(head:str, key:str):
    for line in head.strip().splitlines():
        if line.startswith(f"{key}:"):
            return line.split(":", 1)[1].strip()
    return ''


def CatchErrorMessage(res):
    import re
    _match=[]
    pattern = re.compile(r"(Fatal error|Deprecated|Warning).*? in .*? on line .*?\d+", re.DOTALL)
    _match = pattern.search(res)
    if _match:
        return _match[0]
    else:
        return _match


def DetectBackendApplication(res):
    import re
    # 後綴對應字典
    exts = ['.php', '.aspx', '.asp', '.jsp']
    os='linux'
    for ext in exts:
        pattern = re.compile(rf"[^\s\"'>]+{ext}(?=[^A-Za-z0-9]|$)", re.IGNORECASE)
        match = pattern.findall(res)
        if match:  
            for i in match:
                if bool(re.match(r'^[A-Za-z]:[\\/]', i)):
                    os='windows'
                    break
            return [os,ext, match]
    return []


def catch_apache(head:str) -> str:
    pattern = re.compile(r'(?i)\bapache(?:/\d+(?:\.\d+)*)?\b')
    m = pattern.search(head)
    return m.group(0) if m else ''


def catch_php(head: str) -> str:
    pattern = re.compile(r'(?i)\bphp(?:/\d+(?:\.\d+)*)?\b')
    m = pattern.search(head)
    return m.group(0) if m else ''

