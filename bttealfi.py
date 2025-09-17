# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

import os
import sys
import json
from datetime import datetime
from lib.SettingData import ExploitDataSetting
from lib import InitializationArgv
from core import TestingWeb


def logo(version,url=''):
    print()
    print(f'     /{InitializationArgv.ANSIcolors.INFO} ┳┓┏┳┓     ┓ ┏┓┳{InitializationArgv.ANSIcolors.RESET}  {version}')
    print(f'    / {InitializationArgv.ANSIcolors.INFO} ┣┫ ┃ ╋┏┓┏┓┃ ┣ ┃{InitializationArgv.ANSIcolors.RESET}')
    print(f' . /  {InitializationArgv.ANSIcolors.INFO} ┻┛ ┻ ┗┗ ┗┻┗┛┻ ┻{InitializationArgv.ANSIcolors.RESET}  {url}')
    print()



def main(argv):

    # 接收命令參數
    exp_args = InitializationArgv.ProGramARGS(argv)

    bttealfi_version='v2.0 (beta)'
    logo(bttealfi_version,'https://github.com/BTtea/BTteaLFI')

    print("[!] legal disclaimer: Usage of bttealfi for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program\n")

    print(f"[*] starting @ {datetime.now().strftime('%H:%M:%S')} /{datetime.now().strftime('%Y-%m-%d')}/\n")

    # 處理命令設定的參數，將設定參數整理設定好
    target=ExploitDataSetting(exp_args,bttealfi_version)

    # debug 參數是否有誤
    InitializationArgv.ParamDebug(target)

    # Check website is OK
    print(InitializationArgv.MsgEvent(target.DebugLevel(),'INFO','testing connection URL'),end='')
    try:
        res_content=TestingWeb.test_connectivity(target)
    except:
        print(InitializationArgv.MsgEvent(target.DebugLevel(),'CRITICAL',"can't establish connection"),end='')
        exit(0)

    # debug http code
    if res_content.status_code!=200:
        print(InitializationArgv.MsgEvent(target.DebugLevel(),'DEBUG',f'got the http code {res_content.status_code}'),end='')
    
    if not os.path.exists('.saves'):
        os.makedirs('.saves')

    if target.args.flush_session:
        if os.path.isfile(f'.saves/{target.url.domain}/{target.url.domain}.json'):
            os.remove(f'.saves/{target.url.domain}/{target.url.domain}.json')

    # 如有發現弱點紀錄則顯示
    result={}
    if os.path.isfile(f'.saves/{target.url.domain}/{target.url.domain}.json'):
        with open(f'.saves/{target.url.domain}/{target.url.domain}.json', "r", encoding="utf-8") as f:
            result = json.load(f)
    else:
        # Check OS and Backend technique
        print(InitializationArgv.MsgEvent(target.DebugLevel(),'DEBUG','Inspecting for exploitable information in the HTTP response headers.'),end='')
        target.backend_system = InitializationArgv.CheckBackendApp(target,res_content.head)
        target.args.backend_app=target.backend_system.app.lower()
        if target.backend_system.os_type.lower():
            target.args.os=target.backend_system.os_type.lower()

        # attack test
        result=TestingWeb.loading_attack_module(target)
        
        if result:
            if target.backend_system.os_type:
                result['os_type'] = target.backend_system.os_type
            else:
                target.backend_system.os_type = result['os_type']

            if target.backend_system.os_banner == 'Unknown' and result['os_type'] != '':
                result['os_banner'] = result['os_type'].capitalize()
            else:
                result['os_banner'] = target.backend_system.os_banner

            result['os_version'] = target.backend_system.os_version
            result['app']        = target.backend_system.app
            result['app_banner'] = target.backend_system.app_banner


    # show payload
    if result and result['technique']:
        InitializationArgv.ShowFindingPayloads(result)
        
        if not os.path.exists(f'.saves/{target.url.domain}'):
            os.makedirs(f'.saves/{target.url.domain}')

        save_path=f".saves/{target.url.domain}/{target.url.domain}.json"
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=4)
            target.backend_system.os_version = result['os_version']
            target.backend_system.os_type    = result['os_type']
            target.backend_system.app        = result['app']
            target.backend_system.app_banner = result['app_banner']
            target.backend_system.os_banner  = result['os_banner']
 
        file_path = os.path.join(os.getcwd(),save_path)
        file_path = os.path.normpath(file_path)
        print(InitializationArgv.MsgEvent(target.DebugLevel(),'INFO',f"fetched data logged to text files under '{file_path}'"),end='')

    else:
        print(InitializationArgv.MsgEvent(target.DebugLevel(),'CRITICAL',"all tested parameters do not appear to be injectable. Try to increase values for '--level' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper dotslashobfuscate') and/or switch '--random-agent'"),end='')


    if result and result['technique'] and target.args.lfi_shell:
        if not bool(target.args.detect_prefix) and not bool(target.args.detect_suffix):
            print(InitializationArgv.MsgEvent(target.DebugLevel(),'WARNING',"Detected that '--detect-prefix' or '--detect-suffix' are not set; by default, the entire webpage content will be captured."),end='')
        TestingWeb.loading_dump_file_module(target,result)


    # if result and result['technique'] and target.args.os_shell:
    #     TestingWeb.loading_get_shell_module(target,result)


    print(f"\n[*] ending @ {datetime.now().strftime('%H:%M:%S')} /{datetime.now().strftime('%Y-%m-%d')}/\n")
    exit(0)


if __name__ == '__main__':
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        print('Received Ctrl+C interrupt signal')
