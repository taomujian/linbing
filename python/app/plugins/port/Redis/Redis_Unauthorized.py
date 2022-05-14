#! /usr/bin/env python3

import redis
from urllib.parse import urlparse

class Redis_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Redis Unauthorized',
            'description': 'Redis Unauthorized Vulnerability',
            'date': '',
            'exptype': 'check',
            'type': 'Unauthorized'
        }
        self.url = url
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not url_parse.port:
            self.port = '6379'
        self.osname = 'Unknown'

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            self.conn = redis.Redis(host = self.host, port = self.port, decode_responses = True)
            self.conn.set('qwer', 12)
            return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    Redis_Unauthorized = Redis_Unauthorized_BaseVerify('http://192.168.0.13:6379')
    print(Redis_Unauthorized.webshell('ids'))




