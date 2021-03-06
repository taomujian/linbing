#!/usr/bin/env python3

'''
name: Oracle 弱口令漏洞
description: Oracle 弱口令漏洞
'''

import cx_Oracle
from urllib.parse import urlparse

class Oracle_Weakpwd_BaseVerify:
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
                conn = cx_Oracle.connect('sys', pwd, self.host + ':1521/orcl')
                print ('存在Oracle弱口令,弱口令为:', pwd)
                conn.close()
                return True
            except Exception as e:
                #print(e)
                pass
            finally:
                pass
        print('不存在Oracle弱口令')
        return False

if  __name__ == "__main__":
    Oracle_Weakpwd = Oracle_Weakpwd_BaseVerify('http://127.0.0.1')
    Oracle_Weakpwd.run()