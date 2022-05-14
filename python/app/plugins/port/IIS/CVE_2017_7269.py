#!/usr/bin/env python3

import socket
from urllib.parse import urlparse

class CVE_2017_7269_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2017-7269 远程代码执行漏洞',
            'description': 'CVE-2017-7269 远程代码执行漏洞,影响范围为: IIS 6.0',
            'date': '2017-03-26',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        self.timeout = 3
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '80'

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            socket.setdefaulttimeout(self.timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, int(self.port)))
            pay = b"OPTIONS / HTTP/1.0\r\n\r\n"
            s.send(pay)
            data = s.recv(2048)
            if b"PROPFIND" in data and b"Microsoft-IIS/6.0" in data :
                # print('存在CVE-2017-7269 远程代码执行漏洞')
                return True
        except Exception as e:
            # print(e)
            pass
        finally:
            try:
                s.close()
            except:
                pass

if __name__ == "__main__":
   CVE_2017_7269 = CVE_2017_7269_BaseVerify('https://baidu.com')
   CVE_2017_7269.check()