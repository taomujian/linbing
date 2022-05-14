#!/usr/bin/env python3

import re
from app.lib.common import get_useragent
from app.lib.request import request

class Druid_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Druid 未授权访问漏洞',
            'description': 'Druid 未授权访问漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Unauthorized'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent()
        }

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            req = await request.get(self.url, headers = self.headers) #禁止重定向
            title =re.findall(r"<title>(.*)</title>", await req.text())[0]
            if  "Druid Console" in title :
                return True
        except Exception as e:
            # print(e)
            pass

if __name__ == "__main__":
    Druid_Unauthorized = Druid_Unauthorized_BaseVerify('http://127.0.0.1:8081')
    Druid_Unauthorized.check()
