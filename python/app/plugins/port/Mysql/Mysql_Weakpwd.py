#!/usr/bin/env python3

import pymysql
from urllib.parse import urlparse

class Mysql_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Mysql 弱口令漏洞',
            'description': 'Mysql 弱口令漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Weakpwd'
        }
        self.url = url
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '3306'

    def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
            if pwd != '':
                pwd = pwd.strip()
            try:
                conn = pymysql.connect(host = self.host, port = int(self.port), user = 'root', password = pwd, database = 'mysql')
                print ('存在Mysql弱口令,弱口令为:', pwd)
                conn.close()
                return True
            except Exception as e:
                print(e)
                pass
            finally:
                pass
        print('不存在Mysql弱口令')
        return False

if  __name__ == "__main__":
    Mysql_Weakpwd = Mysql_Weakpwd_BaseVerify('http://10.4.33.38:3306')
    Mysql_Weakpwd.check()