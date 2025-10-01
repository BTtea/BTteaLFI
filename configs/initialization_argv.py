# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.


def ProGramARGS(argv,bttealfi_version):
    from argparse import ArgumentParser,SUPPRESS
    parser = ArgumentParser(prog=argv[0],usage=SUPPRESS)

    # -------------------------
    # Target
    # -------------------------
    g_target = parser.add_argument_group('Target')
    g_target.add_argument("-u", "--url", type=str, required=True, help="input URL")
    g_target.add_argument("--data", type=str, default='', help="POST data")

    # -------------------------
    # General
    # -------------------------
    g_general = parser.add_argument_group('General')
    g_general.add_argument("--version", action="version", version=bttealfi_version,help="Show program's version number and exits")
    g_general.add_argument("-v", type=int, metavar='DEBUG_LEVEL', choices=[0,1,2,3,4,5,6],default=1, help="debug information")

    # -------------------------
    # Request
    # -------------------------
    g_request = parser.add_argument_group('Request')
    g_request.add_argument("--method", type=str, default='GET', help="Method")
    g_request.add_argument("--cookie", type=str, default='', help="cookie session")
    g_request.add_argument("-H", "--header", default=[], action="append", type=str, help="headers")
    g_request.add_argument("--random-agent", default=False, action="store_true",help="Use randomly selected HTTP User-Agent header value")
    g_request.add_argument("--tamper", default='', type=str, help="tamper file")
    g_request.add_argument("--timeout", type=int, metavar='Number', default=5,help="Time to wait for the web page response, default is 5 seconds")
    g_request.add_argument("--retries", type=int, metavar='Number', default=3,help="Number of retries on connection failure, default is 3")

    # -------------------------
    # Testing
    # -------------------------
    g_test = parser.add_argument_group('Testing')
    g_test.add_argument("--prefix", type=str, default='', help="Specify prefix")
    g_test.add_argument("--suffix", type=str, default='', help="Specify suffix")
    g_test.add_argument("--technique", type=str, default=[], help="Specify testing techniques, Support RP, AP, and PHP_F options.")
    g_test.add_argument("--php-wrapper", type=str, default='/etc/passwd',help="Default test keywords for 'php://filter'")
    g_test.add_argument("--level", type=int, choices=[1,2,3], default=1,help="File type detection level, the higher the level, the more file types can be detected. Default: 1")
    g_test.add_argument("--backend-app", type=str, choices=["all","php","aspx","jsp"], default="all",help="Web backend technology (php, asp, jsp). Default: all.")
    g_test.add_argument("--lfi-shell", default=False, action="store_true", help="Prompt for an interactive LFI shell")
    g_test.add_argument("--move", type=int, metavar='Number', default=5,help="Number of path traversal levels, default is 5")
    g_test.add_argument("--path-depth", type=int, metavar='Number', default=0,help="Traversal range for testing LFI path depth, default is 0")
    g_test.add_argument("--skip-xss", default=False, action="store_true", help="Skip XSS payload testing")
    g_test.add_argument("--test-skip", type=str, metavar='Prompt', default='', help="Skip payload tests for the specified prompt.")

    # -------------------------
    # Detection / Output parsing
    # -------------------------
    g_detect = parser.add_argument_group('Detection')
    g_detect.add_argument("--detect-prefix", type=str, default='', help="Context prefix for LFI file output")
    g_detect.add_argument("--detect-suffix", type=str, default='', help="Context suffix for LFI file output")
    g_detect.add_argument("--dump", default=False, action="store_true", help="Convert text output into a download")

    # -------------------------
    # Output & Session
    # -------------------------
    g_session = parser.add_argument_group('Output / Session')
    g_session.add_argument("--batch", default=False, action="store_true", help="Never ask for user input, use the default behavior")
    g_session.add_argument("--answer", type=str, default='', help='Set predefined answers (e.g. "quit=N,follow=N")')
    g_session.add_argument("--flush-session", default=False, action="store_true", help="Flush session files for current target")

    # -------------------------
    # Miscellaneous
    # -------------------------
    g_misc = parser.add_argument_group('Miscellaneous')
    g_misc.add_argument("--os", type=str, metavar='OS type', choices=['windows','linux'], default='all',help="Specify the backend operating system")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p",type=str,default='',metavar='PARAM',help="Specify parameters")
    group.add_argument("--skip",type=str,default='',metavar='PARAM',help="skip parameters")

    return parser.parse_args()
    # parser.add_argument("--os-shell", default=False, action="store_true", help="Prompt for an interactive operating system shell")
    # --cve-2012-1823
    # --cve-2024-4577
    # --cve-2024-2961 param
    # --os-uname
    # /etc/os-release，/etc/lsb-release，/etc/system-release，/etc/issue
    # /etc/issue => Ubuntu 20.04.6 LTS \n \l

    # --string
    # --eval


def ParamDebug(target):
    from lib.utils.my_functions import MsgEvent

    # -------------------------
    # Check GET or POST param
    # -------------------------
    get_query=bool(target.parameters.url.get_query)
    post_query=bool(target.parameters.post.post_query)
    cookie=bool(target.parameters.cookie.cookies)
    mark_url='*' in str(target.parameters.url)
    mark_post='*' in str(target.parameters.post)
    mark_cookie='*' in str(target.parameters.cookie)

    if target.args.level >= 3:
        if (not get_query and not post_query and not cookie) and (not mark_url and not mark_post and not mark_cookie):
            print(MsgEvent(target.debug_level(),'CRITICAL',"no parameter(s) found for testing in the provided data (e.g. GET parameter 'action' in 'www.site.com/index.php?action=*')"))
            exit(0)
    
    elif target.args.level >= 1:
        if (not get_query and not post_query) and (not mark_url and not mark_post):
            print(MsgEvent(target.debug_level(),'CRITICAL',"no parameter(s) found for testing in the provided data (e.g. GET parameter 'action' in 'www.site.com/index.php?action=*')"))
            exit(0)


    # -------------------------
    # Check Specify Params
    # -------------------------
    flag_GET =False if target.parameters.url.get_query else True
    flag_POST=False if target.parameters.post.post_query else True

    # Check inside GET 
    if target.parameters.url.get_query_params:
        for key in target.SpecifyParam():
            if key not in target.parameters.url.get_query_params:
                flag_GET=True
                print(MsgEvent(target.debug_level(),'DEBUG',f"provided parameter '{key}' is not inside the GET"),end='')

    # Check inside POST
    if target.parameters.post.post_query_params and target.parameters.post.content_type == 'application/x-www-form-urlencoded; charset=utf-8':
        for key in target.SpecifyParam():
            if key not in target.parameters.post.post_query_params:
                flag_POST=True
                print(MsgEvent(target.debug_level(),'DEBUG',f"provided parameter '{key}' is not inside the POST"),end='')
    
    if flag_GET and flag_POST:
        print(MsgEvent(target.debug_level(),'CRITICAL',"all testable parameters you provided are not present within the given request data"),end='')
        exit(0)

    # -------------------------
    # Check Skip Params
    # -------------------------
    # Check inside GET
    if target.parameters.url.get_query_params:
        for key in target.SkipParam():
            if key not in target.url.parameters.url.get_query_params:
                print(MsgEvent(target.debug_level(),'DEBUG',f"provided parameter '{key}' is not inside the GET"),end='')
                break
    # Check inside POST
    if target.parameters.post.post_query_params and target.parameters.post.content_type == 'application/x-www-form-urlencoded; charset=utf-8':
        for key in target.SkipParam():
            if key not in target.parameters.post.post_query_params:
                print(MsgEvent(target.debug_level(),'DEBUG',f"provided parameter '{key}' is not inside the POST"),end='')
                break

    # -------------------------
    # path depth and move
    # -------------------------
    if target.args.move!=5 and target.args.path_depth!=0:
        print(MsgEvent(target.debug_level(),'ERROR',f"'--move' and '--path-depth' cannot be used at the same time."),end='')
        exit(0)
    
    if target.args.php_wrapper == '/etc/passwd':
        print(MsgEvent(target.debug_level(),'WARNING',f"Recommend using --php-wrapper to specify the original value (e.g., if vuln.php?action=home, then use '--php-wrapper home') to improve detection of php://filter-based LFI."),end='')

    return

