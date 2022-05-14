#!/usr/bin/env python3

import socket
from urllib.parse import urlparse

class Memcached_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Memcached 未授权访问漏洞',
            'description': 'Memcached 未授权访问漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Unauthorized'
        }
        self.url = url
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '11211'

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, int(self.port)))
            s.send('stats\r\n'.encode('utf-8'))
            if 'version' in s.recv(1024).decode('utf-8'):
                # print('存在Memcached未授权访问')
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
    Memcached_Unauthorized = Memcached_Unauthorized_BaseVerify('http://222.211.90.4:22222')
    Memcached_Unauthorized.check()