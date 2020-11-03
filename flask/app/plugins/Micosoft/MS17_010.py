#!/usr/bin/env python3

'''
name: MS17-010漏洞
description: MS17-010SMB远程溢出漏洞,端口139,445
'''

import socket
import binascii
from urllib.parse import urlparse

class MS17_010_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.timeout = 20
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = str(url_parse.port)
        if not self.port:
            self.port = ['139', '445']
        self.flag = 0
        
    def run(self):
        negotiate_protocol_request = binascii.unhexlify(
            "00000054ff534d42720000000018012800000000000000000000000000002f4b0000c55e003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200")
        session_setup_request = binascii.unhexlify(
            "00000063ff534d42730000000018012000000000000000000000000000002f4b0000c55e0dff000000dfff02000100000000000000000000000000400000002600002e0057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
        for port in self.port:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((self.host, int(port)))
                s.send(negotiate_protocol_request)
                s.recv(1024)
                s.send(session_setup_request)
                data = s.recv(1024)
                user_id = data[32:34]
                tree_connect_andx_request = "000000%xff534d42750000000018012000000000000000000000000000002f4b%sc55e04ff000000000001001a00005c5c%s5c49504324003f3f3f3f3f00" % ((58 + len(self.host)), user_id.hex(), self.host.encode('ascii').hex())
                s.send(binascii.unhexlify(tree_connect_andx_request))
                data = s.recv(1024)
                allid = data[28:36]
                payload = "0000004aff534d422500000000180128000000000000000000000000%s1000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00" % allid.hex()
                s.send(binascii.unhexlify(payload))
                data = s.recv(1024)
                s.close()
                if b"\x05\x02\x00\xc0" in data:
                    self.flag = 1
            except Exception as e:
                print(e)
            finally:
                pass
        if self.flag == 1:
            print("存在MS17-010 SMB远程溢出漏洞")
            return True
        else:
            print("不存在MS17-010 SMB远程溢出漏洞")
            return False

if  __name__ == "__main__":
    MS17_010 = MS17_010_BaseVerify('http://baidu.com')
    MS17_010.run()