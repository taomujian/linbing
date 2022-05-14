#!/usr/bin/env python3

import re
import socket
import asyncio
from urllib.parse import urlparse

class Rsync_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Rsync 未授权访问漏洞',
            'description': 'Rsync 未授权访问漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Unauthorized'
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

    def _get_ver_num(self, ver_string=''):
        ver_num_com = re.compile('@RSYNCD: (\d+)')
        if ver_string:
            ver_num = ver_num_com.match(ver_string).group(1)
            if ver_num.isdigit():
                return int(ver_num)
            else: return 0
        else:
            return 0

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        flag = 0
        not_unauth_list = []
        try:
            for path_name in await self.get_all_pathname():
                ret = self.is_path_not_auth(path_name)
                if ret == 0:
                    flag = 1
                    not_unauth_list.append(path_name)
                else:
                    pass
            if flag == 1:
                return True, '未授权访问目录有: ' + ','.join(not_unauth_list)

        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    Rsync_Unauthorized = Rsync_Unauthorized_BaseVerify('http://baidu.com')
    Rsync_Unauthorized.check()
