#!/usr/bin/env python3

'''
name: Druid 未授权访问漏洞
description: Druid 未授权访问漏洞
'''

import re
from app.lib.utils.request import request


class Druid_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0'
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            req = request.get(self.url, headers = self.headers) #禁止重定向
            title =re.findall(r"<title>(.*)</title>", req.text)[0]
            if  "Druid Console" in title :
                print("存在Druid未授权访问漏洞")
                return True
            else:
                print("不存在Druid未授权访问漏洞")
                return False
        except Exception as e:
            print(e)
            print("不存在Druid未授权访问漏洞")
            return False
        finally:
            pass

if __name__ == "__main__":
    Druid_Unauthorized = Druid_Unauthorized_BaseVerify('http://3.91.55.140:8081')
    Druid_Unauthorized.run()
