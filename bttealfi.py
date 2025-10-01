# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

import os
import sys
sys.dont_write_bytecode = True
import json
from datetime import datetime
from configs.initialization_argv import ProGramARGS,ParamDebug
from configs.setting_data import ExploitDataSetting
from lib.utils.my_functions import ANSIcolors,MsgEvent
from lib.http.request_packet import test_connectivity
from lib.detect.detection import CheckBackendApp
from lib.attacks import testing_web
from lib.exploits.lfi_shell import show_finding_payloads


def logo(version,url):
    print()
    print(f'     /{ANSIcolors.INFO} ┳┓┏┳┓     ┓ ┏┓┳{ANSIcolors.RESET}  v{version}')
    print(f'    / {ANSIcolors.INFO} ┣┫ ┃ ╋┏┓┏┓┃ ┣ ┃{ANSIcolors.RESET}')
    print(f' . /  {ANSIcolors.INFO} ┻┛ ┻ ┗┗ ┗┻┗┛┻ ┻{ANSIcolors.RESET}  {url}')
    print()



def main(argv):
    bttealfi_version='2.0#beta.01'
    github_url='https://github.com/BTtea/BTteaLFI'
    # 接收命令參數

    if len(argv) == 1:
        print(f"usage: {argv[0]} [-h | --help]")
        exit(0)

    if '--version' not in argv:
        logo(bttealfi_version,github_url)

    exp_args = ProGramARGS(argv,bttealfi_version)

    print("[!] legal disclaimer: Usage of bttealfi for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program\n")

    print(f"[*] starting @ {datetime.now().strftime('%H:%M:%S')} /{datetime.now().strftime('%Y-%m-%d')}/\n")

    # 處理命令設定的參數，將設定參數整理設定好
    target=ExploitDataSetting(exp_args,bttealfi_version,github_url)
    
    # debug 參數是否有誤
    ParamDebug(target)

    # Check website is OK
    print(MsgEvent(target.debug_level(),'INFO','testing connection URL'),end='')
    try:
        res_content=test_connectivity(target)
    except:
        print(MsgEvent(target.debug_level(),'CRITICAL',"can't establish connection"),end='')
        exit(0)
    
    # debug http code
    if res_content.status_code!=200:
        print(MsgEvent(target.debug_level(),'DEBUG',f'got the http code {res_content.status_code}'),end='')
    
    if not os.path.exists('.saves'):
        os.makedirs('.saves')

    if target.args.flush_session:
        if os.path.isfile(f'.saves/{target.parameters.url.domain}/{target.parameters.url.domain}.json'):
            os.remove(f'.saves/{target.parameters.url.domain}/{target.parameters.url.domain}.json')

    # 如有發現弱點紀錄則顯示
    result={}
    if os.path.isfile(f'.saves/{target.parameters.url.domain}/{target.parameters.url.domain}.json'):
        with open(f'.saves/{target.parameters.url.domain}/{target.parameters.url.domain}.json', "r", encoding="utf-8") as f:
            result = json.load(f)
    else:
        # Check OS and Backend technique
        print(MsgEvent(target.debug_level(),'DEBUG','Inspecting for exploitable information in the HTTP response headers.'),end='')
        target = CheckBackendApp(target,res_content.head)

        # attack test
        result=testing_web.loading_attack_module(target)
        
        if result:
            if target.web_backend_technique.os_type:
                result['os_type'] = target.web_backend_technique.os_type
            else:
                target.web_backend_technique.os_type = result['os_type']

            if target.web_backend_technique.os_banner == 'Unknown' and result['os_type'] != '':
                result['os_banner'] = result['os_type'].capitalize()
            else:
                result['os_banner'] = target.web_backend_technique.os_banner

            result['os_version'] = target.web_backend_technique.os_version
            result['app_type']        = target.web_backend_technique.app_type
            result['app_banner'] = target.web_backend_technique.app_banner


    # show payload
    if result and result['technique']:
        show_finding_payloads(result)
        
        if not os.path.exists(f'.saves/{target.parameters.url.domain}'):
            os.makedirs(f'.saves/{target.parameters.url.domain}')

        save_path=f".saves/{target.parameters.url.domain}/{target.parameters.url.domain}.json"
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=4)
            target.web_backend_technique.os_version = result['os_version']
            target.web_backend_technique.os_type    = result['os_type']
            target.web_backend_technique.app_type   = result['app_type']
            target.web_backend_technique.app_banner = result['app_banner']
            target.web_backend_technique.os_banner  = result['os_banner']
    else:
        print(MsgEvent(target.debug_level(),'CRITICAL',"all tested parameters do not appear to be injectable. Try to increase values for '--level' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper dotslashobfuscate') and/or switch '--random-agent'"),end='')

    if result and result['technique'] and target.args.lfi_shell:
        if not bool(target.args.detect_prefix) and not bool(target.args.detect_suffix):
            print(MsgEvent(target.debug_level(),'WARNING',"Detected that '--detect-prefix' or '--detect-suffix' are not set; by default, the entire webpage content will be captured."),end='')
        testing_web.loading_dump_file_module(target,result)


    # if result and result['technique'] and target.args.os_shell:
    #     TestingWeb.loading_get_shell_module(target,result)

    if result and result['technique']:
        file_path = os.path.join(os.getcwd(),save_path)
        file_path = os.path.normpath(file_path)
        print()
        print(MsgEvent(target.debug_level(),'INFO',f"fetched data logged to text files under '{file_path}'"),end='')


    print(f"\n[*] ending @ {datetime.now().strftime('%H:%M:%S')} /{datetime.now().strftime('%Y-%m-%d')}/\n")
    exit(0)


if __name__ == '__main__':
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        print('Received Ctrl+C interrupt signal')
