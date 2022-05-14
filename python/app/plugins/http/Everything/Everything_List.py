#!/usr/bin/env python3

import re
from app.lib.common import get_useragent
from app.lib.request import request

class Everything_List_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Everything 敏感信息泄露漏洞',
            'description': 'Everything 敏感信息泄露漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Configure'
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
            title =re.findall(r"<title>(.*)</title>", await req.text())[0]
            if "Everything" in title:
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    Everything_List = Everything_List_BaseVerify('http://baidu.com')
    Everything_List.check()