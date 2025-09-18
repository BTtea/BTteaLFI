# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

class ANSIcolors():
    Time        = '\033[38;5;44m'
    TRAFFIC_OUT = '\033[38;2;136;23;152m'
    TRAFFIC_IN  = '\033[48;2;136;23;152m'
    PAYLOAD     = '\033[38;5;44m'
    DEBUG       = '\033[38;5;33m'
    INFO        = '\033[38;5;40m'
    WARNING     = '\033[38;5;184m'
    ERROR       = '\033[38;5;160m'
    CRITICAL    = '\033[48;5;160m'
    BOLD        = "\033[1m"
    UNDERLINE   = '\033[4m'
    RESET       = '\033[0m'

def ProGramARGS(argv):
    from argparse import ArgumentParser
    if len(argv)==1:
        print(f"usage: {argv[0]} [-h]")
        exit(0)
    parser = ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    parser.add_argument("--version",action="version",version="v2.0 (beta)", help="Show program's version number and exits")
    parser.add_argument("-u","--url",type=str,required=True,help="input URL")
    parser.add_argument("--data",type=str,default='',help="POST data")
    parser.add_argument("--method",type=str,default='GET',help="Method")
    parser.add_argument("--cookie",type=str,default='',help="cookie session")
    parser.add_argument("-H","--header",action="append",type=str,help="headers")
    parser.add_argument("--random-agent",default='', action="store_true", help="Use randomly selected HTTP User-Agent header value")
    parser.add_argument("--tamper",default='',type=str,help="tamper file")
    parser.add_argument("-v",type=int,metavar='DEBUG_LEVEL',choices=[0,1,2,3,4,5,6],default=1,help="debug information")
    parser.add_argument("--os",type=str,metavar='OS type',choices=['windows','linux','all'],default='all',help="Specify the backend operating system")
    parser.add_argument("--prefix",type=str,default='',help="Specify prefix")
    parser.add_argument("--suffix",type=str,default='',help="Specify suffix")
    parser.add_argument("--technique",type=str,default='',help="Specify testing techniques, Support RP, AP, and PHP_F options.")
    parser.add_argument("--php-wrapper",type=str,default='/etc/passwd', help="Default test keywords for 'php://filter'")
    parser.add_argument("--level",type=int,choices=[1,2,3],default=1,help="File type detection level — the higher the level, the more file types can be detected. Default: 1")
    parser.add_argument("--backend-app",type=str,choices=["all","php","aspx","jsp"],default="all",help="Web backend technology (php, asp, jsp). Default: all.")
    parser.add_argument("--batch", default=False, action="store_true", help="Never ask for user input, use the default behavior")
    parser.add_argument("--answer",type=str,default='',help='Set predefined answers (e.g. "quit=N,follow=N")')
    parser.add_argument("--move",type=int,metavar='Number',default=5,help="Number of path traversal levels, default is 5")
    parser.add_argument("--retries",type=int,metavar='Number',default=3,help="Number of retries on connection failure, default is 3")
    parser.add_argument("--path-depth",type=int,metavar='Number',default=0,help="Traversal range for testing LFI path depth, default is 0")
    parser.add_argument("--skip-xss", default=False, action="store_true", help="Skip XSS payload testing")
    parser.add_argument("--test-skip",type=str,metavar='Prompt',default='',help="Skip payload tests for the specified prompt.")
    parser.add_argument("--flush-session", default=False, action="store_true", help="Flush session files for current target")
    parser.add_argument("--lfi-shell", default=False, action="store_true", help="Prompt for an interactive LFI shell")
    parser.add_argument("--detect-prefix",type=str,default='', help="Context prefix for LFI file output")
    parser.add_argument("--detect-suffix",type=str,default='', help="Context suffix for LFI file output")
    parser.add_argument("--dump", default=False, action="store_true", help="Convert text output into a download")
    parser.add_argument("--timeout",type=int,metavar='Number',default=5,help="Time to wait for the web page response, default is 5 seconds")
    
    # parser.add_argument("--os-shell", default=False, action="store_true", help="Prompt for an interactive operating system shell")
    
    # --os-uname
    # /etc/os-release，/etc/lsb-release，/etc/system-release，/etc/issue
    # /etc/issue => Ubuntu 20.04.6 LTS \n \l

    # --string
    # --eval

    group.add_argument("-p",type=str,default='',metavar='PARAM',help="Specify parameters")
    group.add_argument("--skip",type=str,default='',metavar='PARAM',help="skip parameters")
    return parser.parse_args()


def MsgEvent(debug_level:int,event:str,CurrntMsg:str,BoldFlag=False) -> str:
    from datetime import datetime
    bold=f'{ANSIcolors.BOLD}' if BoldFlag else ''
    EventColor={
        'ERROR'       : f'[{bold}{ANSIcolors.ERROR}ERROR{ANSIcolors.RESET}]',
        'CRITICAL'    : f'[{bold}{ANSIcolors.CRITICAL}CRITICAL{ANSIcolors.RESET}]',
        'INFO'        : f'[{bold}{ANSIcolors.INFO}INFO{ANSIcolors.RESET}]',
        'WARNING'     : f'[{bold}{ANSIcolors.WARNING}WARNING{ANSIcolors.RESET}]',
        'DEBUG'       : f'[{bold}{ANSIcolors.DEBUG}DEBUG{ANSIcolors.RESET}]',
        'PAYLOAD'     : f'[{bold}{ANSIcolors.PAYLOAD}PAYLOAD{ANSIcolors.RESET}]',
        'TRAFFIC OUT' : f'[{bold}{ANSIcolors.TRAFFIC_OUT}TRAFFIC OUT{ANSIcolors.RESET}]',
        'TRAFFIC IN'  : f'[{bold}{ANSIcolors.TRAFFIC_IN}TRAFFIC IN{ANSIcolors.RESET}]'
    }
    Msg=''
    if debug_level>=5 and event in ['TRAFFIC IN']:
        Msg=f"[{ANSIcolors.Time}{datetime.now().strftime('%H:%M:%S')}{ANSIcolors.RESET}] "
        Msg+=f'{EventColor[event]} {bold}{CurrntMsg}{ANSIcolors.RESET}\n'
    if debug_level>=4 and event in ['TRAFFIC OUT']:
        Msg=f"[{ANSIcolors.Time}{datetime.now().strftime('%H:%M:%S')}{ANSIcolors.RESET}] "
        Msg+=f'{EventColor[event]} {bold}{CurrntMsg}{ANSIcolors.RESET}\n'
    elif debug_level>=3 and event in ['PAYLOAD']:
        Msg=f"[{ANSIcolors.Time}{datetime.now().strftime('%H:%M:%S')}{ANSIcolors.RESET}] "
        Msg+=f'{EventColor[event]} {bold}{CurrntMsg}{ANSIcolors.RESET}\n'
    elif debug_level>=2 and event in ['DEBUG']:
        Msg=f"[{ANSIcolors.Time}{datetime.now().strftime('%H:%M:%S')}{ANSIcolors.RESET}] "
        Msg+=f'{EventColor[event]} {bold}{CurrntMsg}{ANSIcolors.RESET}\n'
    elif debug_level>=1 and event in ['INFO','WARNING']:
        Msg=f"[{ANSIcolors.Time}{datetime.now().strftime('%H:%M:%S')}{ANSIcolors.RESET}] "
        Msg+=f'{EventColor[event]} {bold}{CurrntMsg}{ANSIcolors.RESET}\n'
    elif debug_level>=0 and event in ['ERROR','CRITICAL']:
        Msg=f"[{ANSIcolors.Time}{datetime.now().strftime('%H:%M:%S')}{ANSIcolors.RESET}] "
        Msg+=f'{EventColor[event]} {bold}{CurrntMsg}{ANSIcolors.RESET}\n'
    
    return Msg


def ParamDebug(ExploitArgv):

    # Check GET or POST param
    if ((not ExploitArgv.url.get_param) and (not ExploitArgv.body.post_param)) and ('*' not in str(ExploitArgv.url) and '*' not in str(ExploitArgv.body)):
        print(MsgEvent(ExploitArgv.DebugLevel(),'CRITICAL',"no parameter(s) found for testing in the provided data (e.g. GET parameter 'action' in 'www.site.com/index.php?action=*')"))
        exit(0)

    # Check Specify Params
    flag_GET =False
    flag_POST=False

    # Check inside GET 
    if ExploitArgv.url.get_param:
        for key in ExploitArgv.SpecifyParam():
            if key not in ExploitArgv.url.get_param:
                flag_GET=True
                print(MsgEvent(ExploitArgv.DebugLevel(),'DEBUG',f"provided parameter '{key}' is not inside the GET"),end='')
                break
    # Check inside POST
    if ExploitArgv.body.post_param and ExploitArgv.body.DataType=='query':
        for key in ExploitArgv.SpecifyParam():
            if key not in ExploitArgv.body.post_param:
                flag_POST=True
                print(MsgEvent(ExploitArgv.DebugLevel(),'DEBUG',f"provided parameter '{key}' is not inside the POST"),end='')
                break

    if flag_GET and flag_POST:
        print(MsgEvent(ExploitArgv.DebugLevel(),'CRITICAL',"all testable parameters you provided are not present within the given request data"),end='')
        exit(0)

    # Check Skip Params
    # Check inside GET
    if ExploitArgv.url.get_param:
        for key in ExploitArgv.SkipParam():
            if key not in ExploitArgv.url.get_param:
                print(MsgEvent(ExploitArgv.DebugLevel(),'DEBUG',f"provided parameter '{key}' is not inside the GET"),end='')
                break
    # Check inside POST
    if ExploitArgv.body and ExploitArgv.body.DataType=='query':
        for key in ExploitArgv.SkipParam():
            if key not in ExploitArgv.body.post_param:
                print(MsgEvent(ExploitArgv.DebugLevel(),'DEBUG',f"provided parameter '{key}' is not inside the POST"),end='')
                break
    
    # path depth and move
    if ExploitArgv.args.move!=5 and ExploitArgv.args.path_depth!=0:
        print(MsgEvent(ExploitArgv.DebugLevel(),'ERROR',f"'--move' and '--path-depth' cannot be used at the same time."),end='')
        exit(0)

    return



def AskQuestion(question:str,_choices,default:str,_target):
    default=default.upper()
    _choices=list(map(str.upper, _choices))

    while True:
        choice=''
        print(f"{ANSIcolors.BOLD}{question}{ANSIcolors.RESET}",end='')

        if _target.args.batch:
            if _target.answer():
                for current_ans in _target.answer():
                    try:
                        if current_ans.split('=')[0] in question:
                            choice=current_ans.split('=')[1].upper()
                    except:
                        print('\n'+MsgEvent(_target.DebugLevel(),'ERROR',f"Incorrect usage of the '--answer' option. Refer to the correct format (e.g. \"quit=N,follow=N\")"),end='')
                        exit(0)
                    
                    if current_ans.split('=')[0] in question and choice not in _choices:
                        print('\n'+MsgEvent(_target.DebugLevel(),'ERROR',f"Incorrect usage of the '--answer' option. Refer to the correct format (e.g. \"quit=N,follow=N\")"),end='')
                        exit(0)

                    if choice!='':
                        break

            if choice=='':
                choice=default
                break

        else:
            choice=input().upper()

        if choice in _choices:
            if _target.args.batch:
                print(choice)
            return choice

    if _target.args.batch:
        print(choice)

    return default



def CheckBackendApp(target,head:str):
    import lib.BackendSystem
    obj=lib.BackendSystem.WebTechnique()
    
    backend_apps=['php','asp','aspx','jsp','nodejs']
    head_tmp=head.lower()
    for i in backend_apps:
        choice=''
        backend_flag=False
        if i in head_tmp:
            backend_flag=True
            print(MsgEvent(target.DebugLevel(),'INFO',f"Detected that the HTTP response headers disclose the backend technology as '{i.upper()}'.",BoldFlag=True),end='')

        if target.url.uri.endswith(i):
            backend_flag=True
            print(MsgEvent(target.DebugLevel(),'INFO',f"Detected URI suffix is '.{i}'.",BoldFlag=True),end='')

        if backend_flag:
            question=f"The detected backend technology appears to be '{i.upper()}'. Would you like to skip payload tests targeting other backend technologies? [Y/n] "
            _choices=['Y','n']
            default='Y'
            res=AskQuestion(question,_choices,default,target)

            if res=='Y':
                obj.app=i.upper()
                target.args.backend_app=i.upper()
                break
            
            if obj.app=='' and target.args.backend_app != 'all':
                obj.app=target.args.backend_app.upper()

    if obj.app=='' and target.args.backend_app != 'all':
        obj.app=target.args.backend_app.upper()


    all_os={
        'CentOS'  : 'Linux',
        'Unix'    : 'Linux',
        'Ubuntu'  : 'Linux',
        'Debian'  : 'Linux',
        'Win32'   : 'Windows',
        'Win64'   : 'Windows'
    }

    for k,v in all_os.items():
        if k.lower() in head.lower():
            obj.os_type=v
            obj.os_version=k
            print(MsgEvent(target.DebugLevel(),'INFO',f"Detected that the HTTP response header discloses the operating system type as '{k}'",BoldFlag=True),end='')

            question=f"The detected operating system appears to be '{v}'. Do you want to skip payload tests intended for other operating systems? [Y/n] "
            _choices=['Y','n']
            default='Y'
            res=AskQuestion(question,_choices,default,target)

            if res=='Y':
                target.args.os=all_os[k]
                obj.os_type=all_os[k]
            
            if obj.os_type=='' and target.args.os != 'all':
                obj.os_type=target.args.os.capitalize()
    
    if obj.os_type=='' and target.args.os != 'all':
        obj.os_type=target.args.os.capitalize()

    X_Powered_By=_GetBanner(head,'X-Powered-By')
    obj.app_banner=_GetBanner(head,'Server').replace(X_Powered_By,'')

    if X_Powered_By:
        obj.app_banner+=f", {X_Powered_By}" if obj.app_banner else X_Powered_By
    elif obj.app:
        obj.app_banner+=f", {obj.app}" if obj.app_banner else obj.app
    if obj.app_banner=='':
        obj.app_banner='Unknown'
    if obj.os_version != '':
        obj.os_banner=f'{obj.os_version} {obj.os_type}'
    else:
        obj.os_banner='Unknown'

    return obj


def ShowFindingPayloads(answer):
    print(
        '---\n'
        f"Parameter: {answer['technique'][0]['Parameter_Name']} ({answer['technique'][0]['HTTP_method']})"
    )
    path_depth=0
    for i in range(len(answer['technique'])):
        if answer['technique'][i]['Type']=='relative path':
            path_depth=answer['technique'][i]['move']
        print(
            f"    Type: {answer['technique'][i]['Type']} " + 
            (f"- {path_depth} Traversal depth\n" if path_depth != 0 else "\n") + 
            f"    Payload: {answer['technique'][i]['Payload']}"
        )
        if len(answer['technique'])-1 != i:
            print()
    print('---')
    print(f"web server operating system: {answer['os_banner']}")
    print(f"web application technology: {answer['app_banner']}")

    return


def _GetBanner(head:str, key:str):
    for line in head.strip().splitlines():
        if line.startswith(f"{key}:"):
            return line.split(":", 1)[1].strip()
    return ''

