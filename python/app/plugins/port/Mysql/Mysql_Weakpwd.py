#!/usr/bin/env python3

import asyncio
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
            conn = pymysql.connect(host = host, port = int(port), user = user, password = pwd, database = 'mysql', connect_timeout = 3, read_timeout = 3, write_timeout = 3)
            result = "user: %s pwd: %s" %(user, pwd)
            return True, '存在Mysql弱口令,账号密码为: ' + result
        except Exception as e:
            # print(e)
            pass
        finally:
            try:
                conn.close()
            except:
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
    Mysql_Weakpwd = Mysql_Weakpwd_BaseVerify('http://127.0.0.1:3306')