#!/usr/bin/env python3

import sys
import asyncio
import paramiko
import logging
from urllib.parse import urlparse

logging.disable('ERROR')

class Ssh_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'SSH 弱口令漏洞',
            'description': 'SSH 弱口令漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Weakpwd'
        }
        self.url = url
        self.timeout = 3
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '22'
            
    def handle(self, host, port, user, pwd):

        """
        发送请求,判断内容

        :param str host: ip地址
        :param str port: 端口号
        :param str user: 用户名
        :param str pwd: 密码

        :return bool True or False: 是否存在漏洞
        """

      
        try:
            ssh = paramiko.SSHClient()
            paramiko.util.log_to_file('/dev/null')
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname = host, port = port, username = user, password = pwd, timeout = 5, banner_timeout = 5, auth_timeout = 5, allow_agent = False, look_for_keys = False)
            result = "user: %s pwd: %s" %(user, pwd)
            ssh.close()
            return True, '存在SSH弱口令,账号密码为: ' + result
        except Exception as e:
            # print(e)
            pass

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        tasks = []
        for user in open('app/data/db/username.txt', 'r', encoding = 'utf-8').readlines():
            user = user.strip()
            for pwd in open('app/data/db/password.txt', 'r', encoding = 'utf-8').readlines():
                if pwd != '':
                    pwd = pwd.strip()
                task = asyncio.create_task(asyncio.to_thread(self.handle, self.host, self.port, user, pwd))
                tasks.append(task)

        results = await asyncio.gather(*tasks)
        for result in results:
            if result:
                return True, result[1]

if  __name__ == "__main__":
    Ssh_Weakpwd = Ssh_Weakpwd_BaseVerify('http://127.0.0.1:7001')
    print(asyncio.run(Ssh_Weakpwd.check()))