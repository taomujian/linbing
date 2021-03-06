#!/usr/bin/env python3

'''
name: DNS域传送漏洞
description: DNS域传送漏洞,需要安装dig程序
'''

import os
import re
from urllib.parse import urlparse

class Dns_Transfer_BaseVerify:
    def __init__(self, url):
        self.url = url
        url_parse = urlparse(self.url)
        self.domain = url_parse.netloc

    def run(self):
        try:
            cmd_res = os.popen('nslookup -type=ns %s' %(self.domain)).read()    # fetch DNS Server List
            dns_servers = re.findall('nameserver = ([\w\.]+)', cmd_res)
            if len(dns_servers) == 0:
                print('不存在DNS域传送漏洞')
                return False
            else:
                for server in dns_servers:
                    cmd_res = os.popen('dig @%s axfr %s' % (server, self.domain)).read()
                    print(cmd_res)
                    if cmd_res.find('Transfer failed.') < 0 and cmd_res.find('connection timed out') < 0 and cmd_res.find('XFR size') > 0 :
                        print('存在DNS域传送漏洞,查询结果是:', cmd_res)
                        return True
                print('不存在DNS域传送漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在DNS域传送漏洞')
            return False
        finally:
            pass

if  __name__ == "__main__":
    Dns_Transfer = Dns_Transfer_BaseVerify('http://baidu.com')
    Dns_Transfer.run()