#!/usr/bin/env python3

'''
name: CVE-2020-2551漏洞
description: CVE-2020-2551漏洞可执行任意命令
'''

import socket
import argparse
from urllib.parse import urlparse

class CVE_2020_2551_BaseVerify:
    def __init__(self, url):
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
            pass
        finally:
            if sock!=None:
                sock.close()
        return False

    def run(self):
        try:
            if self.doSendOne(bytes.fromhex('47494f50010200030000001700000002000000000000000b4e616d6553657276696365')):
                print('存在CVE-2020-2551漏洞')
                return True
            else:
                print('不存在CVE-2020-2551')
                return False
        except Exception as e:
            #print(e)
            print('不存在CVE-2020-2551')
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2020_2551 = CVE_2020_2551_BaseVerify('http://172.16.240.141')
    CVE_2020_2551.run()