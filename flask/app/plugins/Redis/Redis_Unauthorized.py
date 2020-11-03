#!/usr/bin/env python3
'''
name: Redis 未授权访问漏洞
description: Redis 未授权访问漏洞
'''

import socket
from urllib.parse import urlparse

class Redis_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.url = url
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '6379'

    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, int(self.port)))
            s.send('INFO\r\n'.encode('utf-8'))
            if 'redis_version' in s.recv(1024).decode('utf-8'):
                print('存在Redis未授权访问')
                s.close()
                return True
            else:
                print('不存在Redis未授权访问')
                s.close()
                return False
        except Exception as e:
            print(e)
            print('不存在Redis未授权访问')
            s.close()
            return False
        finally:
            pass

if  __name__ == "__main__":
    Redis_Unauthorized = Redis_Unauthorized_BaseVerify('http://10.4.16.3:16379')
    Redis_Unauthorized.run()