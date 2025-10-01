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


def RandomString(length=6) -> str:
    from random import choices
    from string import ascii_letters
    return ''.join(choices(ascii_letters, k=length))


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




