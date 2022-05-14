#!/usr/bin/env python3

import base64
import asyncio
from app.lib.common import get_useragent
from app.lib.request import request

class Dubbo_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Dubbo 弱口令漏洞',
            'description': 'Dubbo 弱口令漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Weakpwd'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent()
        }
    
    async def handle(self, user, pwd):
        
        """
        发送请求,判断内容

        :param str user: 用户名
        :param str pwd: 密码

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            verify_str = user + ":" + pwd
            verify_str = base64.b64encode(verify_str)
            self.headers['Authorization'] = 'BASIC ' + verify_str
            req = await request.get(self.url, headers = self.headers)
            if req.status == 200:
                result = "user: %s pwd: %s" %(user, pwd)
                return True, '存在Dubbo弱口令漏洞,弱口令为: ' + result
        except Exception as e:
            # print(e)
            pass

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            req = await request.get(self.url, headers = self.headers)
            if req.headers["www-authenticate"] == "Basic realm=\"dubbo\"":
                tasks = []
                for user in open('app/data/username.txt', 'r', encoding = 'utf-8').readlines():
                    user = user.strip()
                    for pwd in open('app/data/password.txt', 'r', encoding = 'utf-8').readlines():
                        if pwd != '':
                            pwd = pwd.strip()
                        task = asyncio.create_task(self.handle(user, pwd))
                        tasks.append(task)
               
                results = await asyncio.gather(*tasks)
                for result in results:
                    if result:
                        return True, result[1]
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    Dubbo_Weakpwd = Dubbo_Weakpwd_BaseVerify('http://baidu.com')
    Dubbo_Weakpwd.check()