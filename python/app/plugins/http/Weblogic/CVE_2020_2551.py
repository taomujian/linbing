#!/usr/bin/env python3

import socket
from urllib.parse import urlparse

class CVE_2020_2551_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': ' CVE-2020-2551漏洞',
            'description': 'CVE-2020-2551漏洞可执行任意命令,影响范围为: Weblogic 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0 and 12.2.1.4.0',
            'date': '2019-12-10',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '7001'

    def doSendOne(self, data):
        sock = None
        res = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(7)
            server_addr = (self.host, int(self.port))
            sock.connect(server_addr)
            sock.send(data)
            res = sock.recv(20)
            if b'GIOP' in res:
                return True
        except Exception as e:
            # print(e)
            pass
        finally:
            try:
                sock.close()
            except:
                pass

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            if self.doSendOne(bytes.fromhex('47494f50010200030000001700000002000000000000000b4e616d6553657276696365')):
                # print('存在CVE-2020-2551漏洞')
                return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    CVE_2020_2551 = CVE_2020_2551_BaseVerify('http://127.0.0.1:7001/')
    CVE_2020_2551.check()