# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

class WebTechnique():
    def __init__(self,args):
        self.os_user_choose=''
        self.os_type=''
        self.os_version=''
        self.os_banner=''
        self.app_user_choose=''
        self.app_type=''
        self.app_version=''
        self.app_banner=''
        self.http_type=''
        self.http_version=''
        self.http_banner=''
    
    def show_banner(self):
        server_info=''

        op_system='Unknown'
        if self.os_type:
            op_system=self.os_type.capitalize()
        if self.os_distribution:
            op_system=f"{self.os_distribution} {self.os_type.capitalize()}"
        if self.os_banner:
            op_system=f"{self.os_banner} {self.os_type.capitalize()}"
        
        http_server=''
        if self.http_type:
            http_server=self.http_type.capitalize()
        if self.http_banner:
            http_server=self.http_banner

        app_tech=''
        if self.app_type:
            app_tech=self.app_type.upper()
        if self.app_banner:
            app_tech=self.app_banner

        web_tech=[]
        if http_server:
            web_tech.append(http_server)
        if app_tech:
            web_tech.append(app_tech)
        if web_tech == []:
            web_tech = ['Unknown']
        
        server_info+=f"web server operating system: {op_system}\n"
        server_info+=f"web application technology: {', '.join(web_tech)}"

        return server_info
    

    def split_app_version(self):
        if len(self.app_banner.split('/'))>1:
            self.app_type,self.app_version=self.app_banner.split('/')
        else:
            self.app_type=self.app_banner
    
    def split_http_version(self):
        if len(self.http_banner.split('/'))>1:
            self.http_type,self.http_version=self.http_banner.split('/')
        else:
            self.http_type=self.http_banner