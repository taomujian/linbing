#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class Dubbo_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Dubbo 未授权访问漏洞',
            'description': 'Dubbo 未授权访问漏洞',
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
            req = await request.get(self.url, headers = self.headers)
            result = await req.text()
            if "<title>dubbo</title>" in result.lower() :
                # print('存在Dubbo未授权访问漏洞')
                return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    Dubbo_Unauthorized = Dubbo_Unauthorized_BaseVerify('http://baidu.com')
    Dubbo_Unauthorized.check()