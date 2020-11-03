#!/usr/bin/env python3
'''
name: CVE-2017-7269 远程代码执行漏洞
description: CVE-2017-7269 远程代码执行漏洞
'''

import socket
from urllib.parse import urlparse

class CVE_2017_7269_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.timeout = 20
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '80'

    def run(self):
        try:
            socket.setdefaulttimeout(self.timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, int(self.port)))
            pay = b"OPTIONS / HTTP/1.0\r\n\r\n"
            s.send(pay)
            data = s.recv(2048)
            s.close()
            if b"PROPFIND" in data and b"Microsoft-IIS/6.0" in data :
                print('存在CVE-2017-7269 远程代码执行漏洞')
                return True
            else:
                print('不存在CVE-2017-7269 远程代码执行漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在CVE-2017-7269 远程代码执行漏洞')
            return False
        finally:
            pass

if __name__ == "__main__":
   CVE_2017_7269 = CVE_2017_7269_BaseVerify('https://blog.csdn.net')
   CVE_2017_7269.run()