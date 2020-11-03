#!/usr/bin/env python3
'''
name: Redis弱口令漏洞
description: Redis弱口令漏洞
'''

import socket
from urllib.parse import urlparse

class Redis_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.url = url
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '6379'

    def run(self):
        try:
            for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                if pwd != '':
                    pwd = pwd.strip()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.host, int(self.port)))
                pwd = 'AUTH {}\r\n'.format(pwd)
                s.send(pwd.encode('utf-8'))
                if '+OK' in s.recv(1024).decode('utf-8'):
                    print('Redis存在弱口令')
                    s.close()
                    return True
            print('不存在Redis弱口令')
            s.close()
            return False
        except Exception as e:
            print(e)
            print('不存在Redis弱口令')
            s.close()
            return False
        finally:
            pass

if __name__ == "__main__":
    Redis_Weakpwd = Redis_Weakpwd_BaseVerify('http://10.4.16.3:16379')
    Redis_Weakpwd.run()