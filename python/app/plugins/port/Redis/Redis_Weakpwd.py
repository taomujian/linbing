#!/usr/bin/env python3

import socket
import asyncio
from urllib.parse import urlparse

class Redis_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Redis弱口令漏洞',
            'description': 'Redis弱口令漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Weakpwd'
        }
        self.url = url
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '6379'
    
    def handle(self, host, port, pwd):

        """
        发送请求,判断内容

        :param str host: ip地址
        :param str port: 端口号
        :param str pwd: 密码

        :return bool True or False: 是否存在漏洞
        """

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, int(port)))
            send_pwd = 'AUTH {}\r\n'.format(pwd)
            s.send(send_pwd.encode('utf-8'))
            if '+OK' in s.recv(1024).decode('utf-8'):
                return True, '存在Redis弱口令,密码为: ' + pwd
        except Exception as e:
            # print(e)
            pass
        finally:
            try:
                s.close()
            except:
                pass

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        tasks = []
        for pwd in open('app/data/db/password.txt', 'r', encoding = 'utf-8').readlines():
            if pwd != '':
                pwd = pwd.strip()
            task = asyncio.create_task(asyncio.to_thread(self.handle, self.host, self.port, pwd))
            tasks.append(task)

        results = await asyncio.gather(*tasks)
        for result in results:
            if result:
                return True, result[1]

if __name__ == "__main__":
    import time
    from concurrent.futures import ThreadPoolExecutor
    executor = ThreadPoolExecutor(39)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # loop = asyncio.get_running_loop()
    loop.set_default_executor(executor)
    time_start = time.time()  # 记录开始时间
    Redis_Weakpwd = Redis_Weakpwd_BaseVerify('http://127.0.0.1:6379')
    # print(asyncio.run(Ssh_Weakpwd.check()))
    print(loop.run_until_complete(Redis_Weakpwd.check()))
    time_end = time.time()  # 记录结束时间
    time_sum = time_end - time_start  # 计算的时间差为程序的执行时间，单位为秒/s
    print(time_sum)