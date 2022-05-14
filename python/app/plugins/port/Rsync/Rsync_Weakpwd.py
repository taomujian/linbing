#!/usr/bin/env python3

import re
import socket
import asyncio
import hashlib
from base64 import b64encode
from urllib.parse import urlparse

class Rsync_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Rsync 弱口令访问漏洞',
            'description': 'Rsync 弱口令访问漏洞',
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
            self.port = '80'
        self.sock = None

    def _rsync_init(self):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket.setdefaulttimeout(self.timeout)
        sock.connect((self.host, int(self.port)))
        sock.send(b'@RSYNCD: 31\n')
        res = sock.recv(1024)
        self.sock = sock
        return res

    def is_path_not_auth(self, path_name = ''):
        self._rsync_init()
        payload = path_name + '\n'
        self.sock.send(payload.encode('utf-8'))
        result = self.sock.recv(1024).decode('utf-8')
        if result == '\n':
            result = self.sock.recv(1024)
        if result.startswith('@RSYNCD: OK'):
            return 0
        if result.startswith('@RSYNCD: AUTHREQD'):
            return 1
        if '@ERROR: chdir failed' in result:
            return -1
        else:
            return -1

    async def get_all_pathname(self):
        path_name_list = []
        self._rsync_init()
        self.sock.send(b'\n')
        await asyncio.sleep(0.5)
        result = self.sock.recv(1024).decode('utf-8')
        if result:
            for path_name in re.split('\n', result):
                if path_name and not path_name.startswith('@RSYNCD: '):
                    path_name_list.append(path_name.split('\t')[0].strip())

        return path_name_list

    def weak_passwd_check(self, path_name='', username='', passwd=''):
        ver_string = self._rsync_init()
        if self._get_ver_num(ver_string=ver_string) < 30:
            pass
            # print('Error info:', ver_string)
        
        payload = path_name + '\n'
        self.sock.send(payload.encode())
        result = self.sock.recv(1024).decode()
        if result == '\n':
            result = self.sock.recv(1024).decode()
        
        if result:
            hash_o = hashlib.md5()
            hash_o.update(passwd.encode())
            hash_o.update((result[18:].rstrip('\n')).encode())
            auth_string = b64encode(hash_o.digest()).decode()
            send_data = username + ' ' + auth_string.rstrip('==') + '\n'
            self.sock.send(send_data.encode())
            res = self.sock.recv(1024).decode()
            if res.startswith('@RSYNCD: OK'):
                return (True, username, passwd)

    def _get_ver_num(self, ver_string=''):
        ver_num_com = re.compile('@RSYNCD: (\d+)')
        if ver_string:
            ver_num = ver_num_com.match(ver_string.decode()).group(1)
            if ver_num.isdigit():
                return int(ver_num)
            else: return 0
        else:
            return 0
    
    def handle(self, path_name, user, pwd):

        """
        发送请求,判断内容

        :param str path_name: 目录
        :param str user: 用户名
        :param str pwd: 密码

        :return bool True or False: 是否存在漏洞
        """

        try:
            res = self.weak_passwd_check(path_name, user, pwd)
            if res:
                result = "user: %s pwd: %s" %(user, pwd)
                return True, '%s目录存在FTP弱口令,账号密码为: %s' %(path_name, result)
            
        except Exception as e:
            # print(e)
            pass

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            tasks = []
            for path_name in await self.get_all_pathname():
                ret = self.is_path_not_auth(path_name)
                if ret == 1:
                    for user in open('app/data/db/username.txt', 'r', encoding = 'utf-8').readlines():
                        user = user.strip()
                        for pwd in open('app/data/db/password.txt', 'r', encoding = 'utf-8').readlines():
                            if pwd != '':
                                pwd = pwd.strip()
                            task = asyncio.create_task(asyncio.to_thread(self.handle, path_name, user, pwd))
                            tasks.append(task)

                    results = await asyncio.gather(*tasks)
                    for result in results:
                        if result:
                            return True, result[1]
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    Rsync_Weakpwd = Rsync_Weakpwd_BaseVerify('http://127.0.0.1:873')
    result = Rsync_Weakpwd.check()
