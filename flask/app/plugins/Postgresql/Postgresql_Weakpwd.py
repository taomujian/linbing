#!/usr/bin/env python3

'''
name: Postgresql 弱口令漏洞
description: Postgresql 弱口令漏洞
'''

import psycopg2
from urllib.parse import urlparse

class Postgresql_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.url = url
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '5432'

    def run(self):
        for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
            if pwd != '':
                pwd = pwd.strip()
            try:
                conn = psycopg2.connect(host = self.host, port = int(self.port), user = 'postgres', password = pwd)
                print ('存在Postgresql弱口令,弱口令为:', pwd)
                conn.close()
                return True
            except Exception as e:
                #print(e)
                pass
            finally:
                pass
        print('不存在Postgresql弱口令')
        return False

if  __name__ == "__main__":
    Postgresql_Weakpwd = Postgresql_Weakpwd_BaseVerify('http://127.0.0.1')
    Postgresql_Weakpwd.run()