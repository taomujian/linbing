#!/usr/bin/env python3

import socket
from urllib.parse import urlparse
from app.lib.common import get_useragent
from app.lib.request import request

class Docker_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Docker 未授权访问漏洞',
            'description': 'Docker 未授权访问漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Unauthorized'
        }
        self.url = url
        self.timeout = 60
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '80'
        self.headers = {
            "User-Agent": get_useragent()
        }

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
            send_str = 'GET /containers/json HTTP/1.1\r\nHost: '+ self.host + ':' + str(self.port) + '\r\n\r\n'
            s.send(send_str.encode('utf-8'))
            recv = s.recv(1024)
            if b"HTTP/1.1 200 OK" in recv and b'Docker' in recv and b'Api-Version' in recv:
                return True
            req = await request.get(self.url + '/info', headers = self.headers)
            if req and 'docker' in await req.text():
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
    Docker_Unauthorized = Docker_Unauthorized_BaseVerify('http://10.4.33.33:9100')
    Docker_Unauthorized.check()