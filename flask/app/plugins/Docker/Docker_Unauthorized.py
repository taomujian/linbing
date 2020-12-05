#!/usr/bin/env python3

'''
name: Docker未验证漏洞
description: Docker未验证漏洞
'''

import socket
from app.lib.utils.request import request
from urllib.parse import urlparse

class Docker_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.timeout = 60
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '80'
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
        }

    def run(self):
        try:
            socket.setdefaulttimeout(self.timeout)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, int(self.port)))
            send_str = 'GET /containers/json HTTP/1.1\r\nHost: '+ self.host + ':' + str(self.port) + '\r\n\r\n'
            s.send(send_str.encode('utf-8'))
            recv = s.recv(1024)
            if b"HTTP/1.1 200 OK" in recv and b'Docker' in recv and b'Api-Version' in recv:
                result = "Docker unauthorized access"
                print('存在Docker未授权访问漏洞')
                return True
            req = request.get(self.url + '/info', headers = self.headers)
            if req and 'docker' in req.text:
                print('存在Docker未授权访问漏洞')
                return True
            else:
                print('不存在Docker未授权访问漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在Docker 未授权访问漏洞')
            return False
        finally:
            pass

if  __name__ == "__main__":
    Docker_Unauthorized = Docker_Unauthorized_BaseVerify('http://10.4.33.33:9100')
    Docker_Unauthorized.run()