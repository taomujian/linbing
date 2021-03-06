#!/usr/bin/env python3

'''
name: FTP 弱口令漏洞
description: FTP 弱口令漏洞
'''

import time
import socket
import ftplib
from urllib.parse import urlparse

class Ftp_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.timeout = 3
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '21'

    def run(self):
        for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
            user = user.strip()
            for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                if pwd != '':
                    pwd = pwd.strip()
                socket.setdefaulttimeout(2)
                ftp = ftplib.FTP()
                time.sleep(1)
                try:
                    ftp.connect(self.host,self.port)
                    ftp.login(user, pwd)
                    print('存在FTP弱口令,账号密码为:', user, pwd)
                    return True
                except Exception as e:
                    ftp.close()
                finally:
                    pass

        print('不存在FTP弱口令')
        return False

if  __name__ == "__main__":
    Ftp_Weakpwd = Ftp_Weakpwd_BaseVerify('http://baidu.com')
    Ftp_Weakpwd.run()
