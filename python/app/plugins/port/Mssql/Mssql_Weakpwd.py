#!/usr/bin/env python3

import socket
import asyncio
import binascii
from urllib.parse import urlparse

class Mssql_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Mssql 弱口令漏洞',
            'description': 'Mssql 弱口令漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Weakpwd'
        }
        self.url = url
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '1433'
        self.data = '0200020000000000123456789000000000000000000000000000000000000000000000000000ZZ5440000000000000000000000000000000000000000000000000000000000X3360000000000000000000000000000000000000000000000000000000000Y373933340000000000000000000000000000000000000000000000000000040301060a09010000000002000000000070796d7373716c000000000000000000000000000000000000000000000007123456789000000000000000000000000000000000000000000000000000ZZ3360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000Y0402000044422d4c6962726172790a00000000000d1175735f656e676c69736800000000000000000000000000000201004c000000000000000000000a000000000000000000000000000069736f5f31000000000000000000000000000000000000000000000000000501353132000000030000000000000000'
    
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
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, int(port)))
            husername = binascii.b2a_hex(user.encode('utf-8'))
            lusername = len(user)
            lpassword = len(pwd)
            hpwd = binascii.b2a_hex(pwd.encode('utf-8'))
            address = binascii.b2a_hex(host.encode('utf-8')) +'3a'.encode('utf-8')+ binascii.b2a_hex(str(port).encode('utf-8'))
            data1 = self.data.replace(self.data[16:16+len(address.decode('utf-8'))], address.decode('utf-8'))
            data2 = data1.replace(data1[78:78+len(husername.decode('utf-8'))], husername.decode('utf-8'))
            data3 = data2.replace(data2[140:140+len(hpwd.decode('utf-8'))], hpwd.decode('utf-8'))
            if lusername >= 16:
                data4 = data3.replace('0X', str(hex(lusername)).replace('0x', ''))
            else:
                data4 = data3.replace('X', str(hex(lusername)).replace('0x', ''))
            if lpassword >= 16:
                data5 = data4.replace('0Y', str(hex(lpassword)).replace('0x', ''))
            else:
                data5 = data4.replace('Y', str(hex(lpassword)).replace('0x', ''))
            hladd = hex(len(host) + len(str(1433))+1).replace('0x', '')
            data6 = data5.replace('ZZ', str(hladd))
            data7 = binascii.a2b_hex(data6)
            s.send(data7)
            if 'master' in s.recv(1024).decode('utf-8'):
                return True, '存在SQL Server弱口令,弱口令为: '  + pwd
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
    Mssql_Weakpwd = Mssql_Weakpwd_BaseVerify('http://127.0.0.1')
    Mssql_Weakpwd.check()